package shapelink.core

import java.nio.ByteBuffer

/** Inner record layer, entirely inside the AEAD plaintext.
  *
  * A cell carries `count` records followed by random padding to fill the cell:
  *
  *   [count: u8]
  *   count * [ kind: u8 | msgId: u32 | fragIdx: u16 | fragCount: u16 | payloadLen: u16 | payload ]
  *   [padding: random bytes to end of capacity]
  *
  * Because the padding is fresh random bytes inside the ciphertext, an observer cannot
  * tell a coalesced cell (many small records) from a cover cell (one dummy record) from
  * a fully-padded last fragment.
  */
enum RecKind(val code: Byte):
  case Data extends RecKind(1)
  case Cover extends RecKind(2)

object RecKind:
  def from(b: Byte): Option[RecKind] = b match
    case 1 => Some(RecKind.Data)
    case 2 => Some(RecKind.Cover)
    case _ => None

final case class Record(kind: RecKind, msgId: Long, fragIdx: Int, fragCount: Int, payload: Array[Byte])

object CellCodec:
  /** kind(1) + msgId(8) + fragIdx(2) + fragCount(2) + payloadLen(2). */
  val RecHdr = 15
  val CountLen = 1
  val MaxCount = 255

  /** Largest payload a single record can carry in a cell of `capacity`. */
  def maxRecordPayload(capacity: Int): Int = capacity - CountLen - RecHdr

  /** Split a message byte stream into fragments that fit one record each. */
  def chunkStream(stream: Array[Byte], capacity: Int): Seq[Array[Byte]] =
    val max = maxRecordPayload(capacity)
    require(max > 0, s"cell too small: capacity=$capacity")
    if stream.isEmpty then Seq(Array.emptyByteArray)
    else stream.grouped(max).toSeq

  def recordsFor(msgId: Long, stream: Array[Byte], capacity: Int): Seq[Record] =
    val chunks = chunkStream(stream, capacity)
    chunks.zipWithIndex.map { (c, i) => Record(RecKind.Data, msgId, i, chunks.length, c) }

  /** Pack as many records as fit into one cell, pad to full capacity with random bytes. */
  def pack(records: Seq[Record], capacity: Int, rng: Rng): Array[Byte] =
    require(records.nonEmpty, "cannot pack an empty cell")
    require(records.length <= MaxCount, s"record count ${records.length} > $MaxCount")
    val out = Array.ofDim[Byte](capacity)
    val bb = ByteBuffer.wrap(out)
    bb.put(records.length.toByte)
    var used = CountLen
    records.foreach { r =>
      require(r.payload.length <= 0xFFFF, "record payload too large")
      bb.put(r.kind.code)
      bb.putLong(r.msgId)
      bb.putShort(r.fragIdx.toShort)
      bb.putShort(r.fragCount.toShort)
      bb.putShort(r.payload.length.toShort)
      bb.put(r.payload)
      used += RecHdr + r.payload.length
    }
    require(used <= capacity, s"records overflow cell: $used > $capacity")
    if used < capacity then
      val pad = new Array[Byte](capacity - used)
      rng.nextBytes(pad) // random, so padding bytes are not identifiable even by pattern
      System.arraycopy(pad, 0, out, used, pad.length)
    out

  def usedBytes(records: Seq[Record]): Int = CountLen + records.map(r => RecHdr + r.payload.length).sum

  /** Returns records, or a failure reason if the cell is malformed. */
  def unpack(bytes: Array[Byte]): Either[String, Seq[Record]] =
    if bytes.isEmpty then Left("empty cell")
    else
      val bb = ByteBuffer.wrap(bytes)
      val count = bb.get() & 0xFF
      val out = scala.collection.mutable.ArrayBuffer.empty[Record]
      var i = 0
      var err: Option[String] = None
      while i < count && err.isEmpty do
        if bb.remaining() < RecHdr then err = Some(s"truncated record header at $i/$count")
        else
          val kindB = bb.get()
          val msgId = bb.getLong()
          val fragIdx = bb.getShort() & 0xFFFF
          val fragCount = bb.getShort() & 0xFFFF
          val len = bb.getShort() & 0xFFFF
          RecKind.from(kindB) match
            case None => err = Some(s"unknown record kind $kindB")
            case Some(k) =>
              if bb.remaining() < len then err = Some(s"truncated payload at $i/$count")
              else
                val p = new Array[Byte](len)
                bb.get(p)
                out += Record(k, msgId, fragIdx, fragCount, p)
        i += 1
      err.toLeft(out.toSeq)
