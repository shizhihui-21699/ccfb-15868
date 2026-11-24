package shapelink.transport

import shapelink.core.*
import shapelink.shape.*
import java.io.{BufferedInputStream, BufferedOutputStream, EOFException, InputStream, OutputStream}
import java.net.{ServerSocket, Socket, SocketException}
import java.util.concurrent.atomic.{AtomicBoolean, AtomicLong}
import java.util.concurrent.{BlockingQueue, LinkedBlockingQueue, TimeUnit}

/** A live, long-lived shaped connection over TCP.
  *
  * This is the piece that makes the design usable rather than merely measurable. Two
  * properties are what make it work on a payment link:
  *
  *  1. **No head-of-line blocking, on the wire as well as in the queue.** The sender uses
  *     one write thread and a `maxHold` send loop, so a cell leaves on the schedule the
  *     shaper chose; it never waits behind a mostly-empty socket buffer.
  *  2. **Write coalescing.** The shaper emits a cell every couple of milliseconds; a
  *     Nagle-less one-write-per-cell pattern would itself be a timing signature. TCP
  *     segmentation is coalesced with `TCP_NODELAY` on and buffered writes, so the
  *     inter-packet gap at the wire has the same distribution as the shaper's schedule.
  *
  * The receiver reads fixed-size cells and hands them to a `Reassembler`. A cell that
  * fails authentication is a hard signal (tamper, key mismatch, desync) and is reported,
  * not silently dropped.
  */
final case class LiveStats(
    cellsSent: Long,
    cellsReceived: Long,
    cellsRejected: Long,
    messagesDelivered: Long,
    bytesOnWire: Long
)

/** One direction of an established connection. */
final class ShapedPipe(
    in: InputStream,
    out: OutputStream,
    val shaper: Shaper,
    val keys: KeySchedule,
    val clock: () => Long = () => System.nanoTime()
):
  private val stop = new AtomicBoolean(false)
  private val reasm = new Reassembler
  private val deliveredQ = new LinkedBlockingQueue[Array[Byte]](1024)
  private val cellsSent = new AtomicLong
  private val cellsRecv = new AtomicLong
  private val cellsRejected = new AtomicLong
  private val delivered = new AtomicLong
  private val bytesWire = new AtomicLong

  private val senderThread = new Thread(() => sendLoop(), "shapelink-send")
  private val receiverThread = new Thread(() => recvLoop(), "shapelink-recv")

  def start(): Unit =
    senderThread.setDaemon(true); receiverThread.setDaemon(true)
    senderThread.start(); receiverThread.start()

  def send(msgId: Long, payload: Array[Byte], svc: ServiceClass): Unit =
    shaper.submit(clock(), msgId, payload, svc)

  /** Blocks until a complete message is reassembled, or None on timeout/stop. */
  def receive(timeoutMs: Long): Option[Array[Byte]] =
    Option(deliveredQ.poll(timeoutMs, TimeUnit.MILLISECONDS))

  def stats: LiveStats =
    LiveStats(cellsSent.get(), cellsRecv.get(), cellsRejected.get(), delivered.get(), bytesWire.get())

  def close(): Unit =
    stop.set(true)
    senderThread.interrupt()
    receiverThread.interrupt()

  private def sendLoop(): Unit =
    val bos = new BufferedOutputStream(out, 64 * 1024)
    try
      while !stop.get() do
        val now = clock()
        val due = shaper.step(now)
        if due.nonEmpty then
          due.foreach { e =>
            bos.write(e.bytes, 0, Wire.HeaderLen)
            bos.write(e.bytes, Wire.HeaderLen, e.bytes.length - Wire.HeaderLen)
            cellsSent.incrementAndGet()
            bytesWire.addAndGet(e.bytes.length.toLong)
            // Keep the shaper's sealing key in step with the epoch schedule.
            keys.onSealed().foreach { newEpoch =>
              keys.keyFor(newEpoch).foreach(k => shaper.rekey(newEpoch, k))
            }
          }
          bos.flush()
        else
          val wake = shaper.nextWakeup(now)
          val sleepNs = if wake == Long.MaxValue then 2_000_000L else math.max(100_000L, math.min(2_000_000L, wake - now))
          TimeUnit.NANOSECONDS.sleep(sleepNs)
    catch
      case _: InterruptedException => ()
      case _: java.io.IOException  => ()

  private def recvLoop(): Unit =
    val bis = new BufferedInputStream(in, 64 * 1024)
    val cellSize = shaper.cfg.cellSize
    val buf = Array.ofDim[Byte](cellSize)
    try
      var go = true
      while go && !stop.get() do
        var read = 0
        while read < cellSize && !stop.get() do
          val n = bis.read(buf, read, cellSize - read)
          if n < 0 then go = false
          else read += n
        if read == cellSize then
          cellsRecv.incrementAndGet()
          val epoch = ByteBuffer.getLongAt(buf, 2)
          keys.acceptEpoch(epoch)
          keys.keyFor(epoch) match
            case None => cellsRejected.incrementAndGet()
            case Some(k) =>
              Wire.openCell(k, buf) match
                case None => cellsRejected.incrementAndGet()
                case Some((_, pt)) =>
                  CellCodec.unpack(pt).toOption.foreach { recs =>
                    recs.foreach { r =>
                      reasm.offer(r).foreach { msg =>
                        delivered.incrementAndGet()
                        deliveredQ.offer(msg)
                      }
                    }
                  }
    catch
      case _: EOFException        => ()
      case _: SocketException     => ()
      case _: java.io.IOException => ()

private object ByteBuffer:
  def getLongAt(b: Array[Byte], off: Int): Long =
    var v = 0L
    var i = 0
    while i < 8 do
      v = (v << 8) | (b(off + i) & 0xFFL)
      i += 1
    v
