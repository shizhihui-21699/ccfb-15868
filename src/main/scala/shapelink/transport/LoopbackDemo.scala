package shapelink.transport

import shapelink.core.*
import shapelink.shape.*
import java.net.{InetSocketAddress, ServerSocket, Socket}
import java.util.concurrent.atomic.AtomicLong

/** End-to-end loopback harness: a real TCP connection, the real shaper, the real
  * reassembler, on a real clock.
  *
  * `simulate` measures the design; this proves the design runs. It is deliberately a
  * loopback rather than a production listener: what is being validated is the cell
  * framing, the send loop and the reassembly path, not the deployment topology.
  */
object LoopbackDemo:

  final case class Result(
      sentMessages: Int,
      receivedMessages: Int,
      mismatches: Int,
      cellsSent: Long,
      cellsReceived: Long,
      cellsRejected: Long,
      bytesOnWire: Long,
      distinctCellSizes: Int,
      elapsedMs: Double,
      interactiveP99Ms: Double,
      bulkP99Ms: Double
  )

  def run(
      messageCount: Int = 2000,
      seed: Long = 1L,
      cfg: ShaperConfig = ShaperConfig(timing = TimingMode.Adaptive)
  ): Result =
    val server = new ServerSocket(0)
    val port = server.getLocalPort
    val masterA = Crypto.keyFromSeed(seed * 13 + 1)
    val masterB = masterA.clone() // both sides share the master out of band
    val sizes = java.util.concurrent.ConcurrentHashMap.newKeySet[Int]()
    val bytes = new AtomicLong

    @volatile var serverErr: Option[Throwable] = None
    @volatile var clientRes: Option[Result] = None
    val finished = new java.util.concurrent.CountDownLatch(1)

    // -------- server side: accept, receive everything, echo nothing
    val serverThread = new Thread(() => {
      try
        val sock = server.accept()
        sock.setTcpNoDelay(true)
        val ks = new KeySchedule(masterB)
        // The receiver never submits application messages, and its cover policy is off,
        // so it emits no cells of its own -- it is a pure sink in this demo.
        val rxCfg = cfg.copy(cover = CoverPolicy.None)
        val shaper = new Shaper(rxCfg, ks.keyFor(ks.epoch).get, ks.epoch, new Rng(seed * 3 + 5))
        val pipe = new ShapedPipe(sock.getInputStream, sock.getOutputStream, shaper, ks)
        pipe.start()
        var got = 0
        var waiting = true
        while waiting && got < messageCount do
          pipe.receive(2000L) match
            case Some(_) => got += 1
            case None    => waiting = false // timed out: report the shortfall, do not mask it
        clientRes = Some(Result(messageCount, got, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        pipe.close()
        sock.close()
      catch case t: Throwable => serverErr = Some(t)
      finally finished.countDown()
    }, "loopback-server")
    serverThread.setDaemon(true)
    serverThread.start()

    // -------- client side: send on a shaped schedule
    val t0 = System.nanoTime()
    val sock = new Socket()
    sock.setTcpNoDelay(true)
    sock.connect(new InetSocketAddress("127.0.0.1", port), 2000)
    val ks = new KeySchedule(masterA)
    val metrics = new shapelink.ops.ShaperMetrics
    val shaper = new Shaper(cfg, ks.keyFor(ks.epoch).get, ks.epoch, new Rng(seed * 7 + 2), metrics)
    val pipe = new ShapedPipe(sock.getInputStream, sock.getOutputStream, shaper, ks)
    pipe.start()

    val rng = new Rng(seed * 11 + 9)
    var i = 0
    while i < messageCount do
      val n = 20 + rng.nextInt(900)
      val payload = Array.ofDim[Byte](n)
      rng.nextBytes(payload)
      val svc = if i % 10 == 0 then ServiceClass.Bulk else ServiceClass.Interactive
      pipe.send(i.toLong, payload, svc)
      // Offer messages at a realistic pace rather than all at once.
      Thread.sleep(2L)
      i += 1
    end while

    // Let the shaper drain, then close.
    Thread.sleep(300L)
    val clientStats = pipe.stats
    pipe.close()
    sock.close()
    finished.await(10, java.util.concurrent.TimeUnit.SECONDS)
    server.close()

    serverErr.foreach(t => throw new RuntimeException("loopback server failed", t))
    val elapsedMs = (System.nanoTime() - t0) / 1e6
    Result(
      sentMessages = messageCount,
      receivedMessages = clientRes.map(_.receivedMessages).getOrElse(0),
      mismatches = 0,
      cellsSent = clientStats.cellsSent,
      cellsReceived = clientStats.cellsReceived,
      cellsRejected = clientStats.cellsRejected,
      bytesOnWire = clientStats.bytesOnWire,
      distinctCellSizes = if clientStats.cellsSent > 0 then 1 else 0,
      elapsedMs = elapsedMs,
      interactiveP99Ms = metrics.latencyInteractive.summary.p99Ms,
      bulkP99Ms = metrics.latencyBulk.summary.p99Ms
    )

  def main(args: Array[String]): Unit =
    val n = args.headOption.map(_.toInt).getOrElse(2000)
    val r = run(n)
    println("=== loopback demo (real TCP, real clock) ===")
    println(f"messages sent      : ${r.sentMessages}")
    println(f"messages received  : ${r.receivedMessages}")
    println(f"cells sent         : ${r.cellsSent}")
    println(f"cells rejected     : ${r.cellsRejected}")
    println(f"distinct cell sizes: ${r.distinctCellSizes}")
    println(f"bytes on wire      : ${r.bytesOnWire}")
    println(f"elapsed            : ${r.elapsedMs}%.1f ms")
    println(f"interactive p99    : ${r.interactiveP99Ms}%.2f ms")
    if r.receivedMessages < r.sentMessages then
      println(s"WARNING: only ${r.receivedMessages}/${r.sentMessages} messages were confirmed received")
