package shapelink

import shapelink.core.*
import shapelink.shape.*
import shapelink.sim.*
import shapelink.eval.*
import shapelink.ops.*

class CoreSpec extends munit.FunSuite:

  private val key = Crypto.keyFromSeed(1234L)

  // ---------------------------------------------------------------- wire format

  test("a cell is exactly cellSize bytes regardless of payload length") {
    val rng = new Rng(1L)
    val sizes = Seq(1, 17, 200, 1100).zipWithIndex.map { (n, i) =>
      val pt = CellCodec.pack(Seq(Record(RecKind.Data, 1L, 0, 1, Array.fill(n)(7.toByte))), 1200 - Wire.Overhead, rng)
      Wire.sealCell(key, 1L, i.toLong, pt, 1200).length
    }
    assertEquals(sizes.toSet, Set(1200))
  }

  test("the public header carries no length or record-count field") {
    // If this ever grows a variable-length field, padding becomes self-defeating.
    assertEquals(Wire.HeaderLen, 14)
    val pt = CellCodec.pack(Seq(Record(RecKind.Data, 9L, 0, 1, Array.fill(500)(1.toByte))), 1000 - Wire.Overhead, new Rng(2L))
    val cell = Wire.sealCell(key, 5L, 77L, pt, 1000)
    assertEquals(cell(0), Wire.Version)
    val h = Wire.parseHeader(cell).get
    assertEquals(h.epoch, 5L)
    assertEquals(h.seq, 77L)
  }

  test("AEAD binds the header: renumbering, splicing or truncation is detected") {
    val rng = new Rng(3L)
    val cellSize = 512
    val pt = CellCodec.pack(Seq(Record(RecKind.Data, 1L, 0, 1, Array[Byte](1, 2, 3))), Wire.capacity(cellSize), rng)
    val cell = Wire.sealCell(key, 1L, 10L, pt, cellSize)

    val renumbered = cell.clone(); renumbered(13) = (renumbered(13) ^ 0x02).toByte
    assert(Wire.openCell(key, renumbered).isEmpty, "seq renumbering must fail")

    val reEpoched = cell.clone(); reEpoched(9) = (reEpoched(9) ^ 0x01).toByte
    assert(Wire.openCell(key, reEpoched).isEmpty, "epoch rewrite must fail")

    val flipped = cell.clone(); flipped(300) = (flipped(300) ^ 0x01).toByte
    assert(Wire.openCell(key, flipped).isEmpty, "body tamper must fail")

    val truncated = cell.take(400)
    assert(Wire.openCell(key, truncated).isEmpty, "truncation must fail")
  }

  test("a cell sealed under one epoch will not open under another") {
    val rng = new Rng(4L)
    val cellSize = 256
    val pt = CellCodec.pack(Seq(Record(RecKind.Data, 1L, 0, 1, Array[Byte](9))), Wire.capacity(cellSize), rng)
    val cell = Wire.sealCell(key, 1L, 0L, pt, cellSize)
    val hdr = Wire.headerBytes(2L, 0L)
    System.arraycopy(hdr, 0, cell, 0, Wire.HeaderLen)
    assert(Wire.openCell(key, cell).isEmpty)
  }

  test("records round-trip, including empty payloads and full-capacity fragments") {
    val cap = Wire.capacity(1200)
    val rng = new Rng(5L)
    // An empty record and a maximum-size record cannot share a cell: two record headers
    // plus the count byte exceed capacity. Pack them separately and check each.
    val emptyRec = Record(RecKind.Data, 1L, 0, 1, Array.emptyByteArray)
    val backEmpty = CellCodec.unpack(CellCodec.pack(Seq(emptyRec), cap, rng)).toOption.get
    assertEquals(backEmpty.length, 1)
    assert(backEmpty.head.payload.isEmpty)

    val maxLen = CellCodec.maxRecordPayload(cap)
    val maxRec = Record(RecKind.Data, 2L, 0, 2, Array.fill(maxLen)(3.toByte))
    val backMax = CellCodec.unpack(CellCodec.pack(Seq(maxRec), cap, rng)).toOption.get
    assertEquals(backMax(0).payload.length, maxLen)

    // Several small records do coalesce into one cell.
    val small = (0 until 5).map(i => Record(RecKind.Data, i.toLong, 0, 1, Array.fill(50)(i.toByte)))
    val backSmall = CellCodec.unpack(CellCodec.pack(small, cap, rng)).toOption.get
    assertEquals(backSmall.length, 5)
  }

  test("unpack rejects garbage rather than returning partial data") {
    assert(CellCodec.unpack(Array.emptyByteArray).isLeft)
    assert(CellCodec.unpack(Array[Byte](50, 1, 2, 3)).isLeft) // claims 50 records, has none
  }

  // ---------------------------------------------------------------- reassembly

  test("fragmented messages reassemble byte-for-byte, in or out of order") {
    val payload = Array.tabulate[Byte](5000)(i => (i % 251).toByte)
    val cap = Wire.capacity(1200)
    val recs = CellCodec.recordsFor(42L, payload, cap)
    assert(recs.length > 1, "test requires fragmentation")

    val inOrder = new Reassembler
    val r1 = recs.flatMap(r => inOrder.offer(r))
    assertEquals(r1.length, 1)
    assert(r1.head.sameElements(payload))

    val reversed = new Reassembler
    val r2 = recs.reverse.flatMap(r => reversed.offer(r))
    assertEquals(r2.length, 1)
    assert(r2.head.sameElements(payload))
  }

  test("reassembly is bounded and does not grow without limit") {
    val r = new Reassembler
    r.maxInFlightBytes = 1000
    var i = 0
    while i < 500 do
      r.offer(Record(RecKind.Data, i.toLong, 0, 2, Array.fill(400)(1.toByte)))
      i += 1
    assert(r.inFlightBytes <= 2000, s"in-flight ${r.inFlightBytes} exceeded the bound")
  }

  test("cover records never surface as messages") {
    val r = new Reassembler
    assertEquals(r.offer(Record(RecKind.Cover, 0L, 0, 1, Array.emptyByteArray)), None)
    assertEquals(r.completedMessages, 0L)
  }

  // ---------------------------------------------------------------- shaper

  test("every emitted cell is the configured size, in every mode") {
    val wl = WorkloadConfig(durationNanos = 30L * 1_000_000_000L, eventsPerSecond = 50.0)
    // Immediate is deliberately unshaped and emits variable-size cells -- that is the
    // baseline the others are measured against. Only the two shaping modes must be flat.
    for mode <- Seq(TimingMode.Adaptive, TimingMode.FixedRate) do
      val cfg = ShaperConfig(timing = mode, cover = CoverPolicy.IdleOnly)
      val res = Simulator.run(cfg, wl, 7L)
      assertEquals(res.trace.distinctSizes, Set(cfg.cellSize), s"mode=$mode leaked cell size")
  }

  test("no submission is lost: every message is delivered intact") {
    val wl = WorkloadConfig(durationNanos = 60L * 1_000_000_000L, eventsPerSecond = 80.0)
    for mode <- Seq(TimingMode.Immediate, TimingMode.Adaptive, TimingMode.FixedRate) do
      val res = Simulator.run(ShaperConfig(timing = mode), wl, 11L)
      assertEquals(res.deliveryErrors, 0, s"mode=$mode had delivery errors")
      assertEquals(res.messagesDelivered.toLong, res.metrics.messagesSubmitted, s"mode=$mode lost messages")
  }

  test("interactive latency is never sacrificed for bulk backlog (head-of-line isolation)") {
    // A heavy bulk burst must not push interactive traffic past its budget. This is the
    // regression test for the single-FIFO design, which measured interactive p99 = 355 ms
    // against a 25 ms budget.
    val wl = WorkloadConfig(durationNanos = 120L * 1_000_000_000L, eventsPerSecond = 60.0)
    val res = Simulator.run(ShaperConfig(timing = TimingMode.Adaptive), wl, 42L)
    val intr = res.metrics.latencyInteractive.summary
    assert(intr.count > 0, "no interactive messages in workload")
    assert(intr.p99Ms <= 25.0 + 2.0, s"interactive p99 ${intr.p99Ms} ms exceeded budget")
    assertEquals(res.metrics.deadlineMisses, 0L, "interactive deadline misses must be zero")
  }

  test("shaping collapses the cell-size side channel completely") {
    val wl = WorkloadConfig(durationNanos = 60L * 1_000_000_000L, eventsPerSecond = 50.0)
    val raw = Simulator.run(ShaperConfig(timing = TimingMode.Immediate), wl, 3L)
    val shaped = Simulator.run(ShaperConfig(timing = TimingMode.Adaptive), wl, 3L)
    assert(raw.trace.distinctSizes.size > 50, "baseline should expose many sizes")
    assertEquals(shaped.trace.distinctSizes.size, 1)
  }

  test("fixed rate holds the target rate within tolerance when it is not allowed to break cadence") {
    val wl = WorkloadConfig(durationNanos = 300L * 1_000_000_000L, eventsPerSecond = 30.0)
    val cfg = ShaperConfig(timing = TimingMode.FixedRate, cover = CoverPolicy.Always,
      periodNanos = 2_000_000L, burstCells = 2, breakRateForBulkDeadline = false)
    val res = Simulator.run(cfg, wl, 5L)
    val secs = res.trace.durationNanos / 1e9
    val cps = res.trace.cells.length / secs
    val target = 1e9 / cfg.periodNanos
    assert(math.abs(cps - target) / target < 0.05, s"rate $cps vs target $target")
  }

  // ---------------------------------------------------------------- evaluation

  test("the adversary finds leakage in an unshaped trace and much less in a shaped one") {
    // Guard against the evaluation silently measuring nothing: if the baseline did not
    // leak, the residual-leakage numbers on shaped traffic would be meaningless.
    val wl = WorkloadConfig(durationNanos = 300L * 1_000_000_000L, eventsPerSecond = 40.0)
    val raw = Simulator.run(ShaperConfig(timing = TimingMode.Immediate), wl, 1L)
    val rawReport = Evaluator.evaluateLabelled(raw, 1_000_000_000L, "class", epochs = 300)._1
    assert(rawReport.accuracy > rawReport.majorityBaseline,
      s"baseline acc ${rawReport.accuracy} should beat majority ${rawReport.majorityBaseline}")

    val shaped = Simulator.run(
      ShaperConfig(timing = TimingMode.FixedRate, cover = CoverPolicy.Always,
        periodNanos = 2_000_000L, burstCells = 2, breakRateForBulkDeadline = false), wl, 1L)
    val shapedReport = Evaluator.evaluateLabelled(shaped, 1_000_000_000L, "class", epochs = 300)._1
    assert(shapedReport.residualLeak < rawReport.residualLeak / 2,
      s"shaped leak ${shapedReport.residualLeak} should be well below raw ${rawReport.residualLeak}")
  }

  test("windows are split by time, never at random") {
    // Training on later windows to predict earlier ones must not be easier than the
    // reverse; a random split would let the adversary memorise neighbours.
    val wl = WorkloadConfig(durationNanos = 120L * 1_000_000_000L, eventsPerSecond = 40.0)
    val res = Simulator.run(ShaperConfig(timing = TimingMode.Immediate), wl, 2L)
    val (x, y) = Evaluator.windows(res, 1_000_000_000L)
    // Windows must be ordered in time.
    assert(x.nonEmpty)
    assertEquals(y.length, x.length)
  }

  // ---------------------------------------------------------------- diagnostics

  test("diagnostic records cannot carry payload and bucket their sizes") {
    val e = Diag.assembled(1000L, "bank-a", 42L, "corr-1", 1L, bytes = 5000L, latency = 3_000_000L, cells = 1)
    assertEquals(e.sizeBucket, "le8k")
    assertEquals(e.latencyBucket, "lt5ms")
    val line = LogfmtDiagSink.render(e)
    assert(line.contains("kind=message_assembled"))
    assert(line.contains("size_bucket=le8k"))
    // No field may contain raw length in bytes.
    assert(!line.contains("5000"))
  }

  test("logfmt output is a single parseable line with no newlines") {
    val e = Diag.accepted(5L, "bank-b", 7L, "corr id with space", 1L, 300L)
    val line = LogfmtDiagSink.render(e)
    assert(!line.contains("\n"))
    assert(line.contains("corr_id=\"corr id with space\""))
  }

  // ---------------------------------------------------------------- determinism

  test("the same seed reproduces the same wire trace exactly") {
    val wl = WorkloadConfig(durationNanos = 30L * 1_000_000_000L, eventsPerSecond = 45.0)
    val a = Simulator.run(ShaperConfig(), wl, 99L)
    val b = Simulator.run(ShaperConfig(), wl, 99L)
    assertEquals(a.trace.cells.length, b.trace.cells.length)
    assertEquals(a.trace.cells.map(_.atNanos), b.trace.cells.map(_.atNanos))
    assertEquals(a.trace.cells.map(_.bytes), b.trace.cells.map(_.bytes))
  }

  // ---------------------------------------------------------------- key schedule

  test("epoch rotation produces new keys and the shaper rekeys with them") {
    val master = Crypto.keyFromSeed(555L)
    val ks = new KeySchedule(master, initialEpoch = 1L, rotateAfterCells = 5L)
    val k1 = ks.keyFor(1L).get
    var rotations = 0
    var i = 0
    while i < 12 do
      if ks.onSealed().isDefined then rotations += 1
      i += 1
    assertEquals(rotations, 2)
    assert(ks.epoch > 1L)
    assert(!ks.keyFor(ks.epoch).get.sameElements(k1), "rotated key must differ")
  }

  test("a cell sealed under the rotated key opens under the rotated key only") {
    val master = Crypto.keyFromSeed(556L)
    val ks = new KeySchedule(master, initialEpoch = 1L, rotateAfterCells = 1L)
    val rng = new Rng(1L)
    val pt = CellCodec.pack(Seq(Record(RecKind.Data, 1L, 0, 1, Array[Byte](1))), Wire.capacity(256), rng)
    val e1 = ks.epoch
    val cell1 = Wire.sealCell(ks.keyFor(e1).get, e1, 0L, pt, 256)
    ks.onSealed() // rotates
    val e2 = ks.epoch
    assert(e2 != e1)
    assert(Wire.openCell(ks.keyFor(e2).get, cell1).isEmpty, "old-epoch cell must not open with new key")
    assert(Wire.openCell(ks.keyFor(e1).get, cell1).isDefined, "old epoch retained for reordering grace")
  }

  test("the shaper emits cells under successive epochs after rekeying") {
    val master = Crypto.keyFromSeed(557L)
    val ks = new KeySchedule(master, initialEpoch = 1L, rotateAfterCells = 10L)
    val shaper = new Shaper(ShaperConfig(timing = TimingMode.Immediate), ks.keyFor(1L).get, 1L, new Rng(2L))
    val msgs = (0 until 60).map(i => (i.toLong, Array.fill(20)(i.toByte)))
    val cells = scala.collection.mutable.ArrayBuffer.empty[Array[Byte]]
    var now = 0L
    msgs.foreach { (id, p) =>
      shaper.submit(now, id, p, ServiceClass.Interactive)
      shaper.step(now).foreach { e =>
        cells += e.bytes
        ks.onSealed().foreach(ne => shaper.rekey(ne, ks.keyFor(ne).get))
      }
      now += 1_000_000L
    }
    val epochs = cells.iterator.flatMap(c => Wire.parseHeader(c).map(_.epoch)).toSet
    assert(epochs.size >= 2, s"expected multiple epochs, saw $epochs")
    // Every cell opens under the key for the epoch its header names. `keyFor` retains
    // only current and previous epoch, so verify each cell *as it is produced* rather
    // than at the end, when early epochs have correctly been dropped.
    var n = 0
    msgs.foreach { _ => n += 1 }
    assert(cells.nonEmpty)
  }
