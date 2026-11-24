package shapelink.ops

import shapelink.core.*

/** A structured, content-free record for operational diagnostics.
  *
  * THE CONSTRAINT THIS SOLVES
  * --------------------------
  * After shaping, the wire carries no useful information for troubleshooting: every cell
  * looks the same, and the payload is opaque. If operations had only packet captures,
  * the natural "fix" would be to log payloads or lengths -- reinstating exactly the leak
  * we are removing.
  *
  * So diagnostics travel *inside the encrypted channel*, on a separate logical stream,
  * and are emitted at both endpoints. An operator at either bank sees message id,
  * business correlation id, timing, cell counts and failure reasons for the traffic
  * that concerns them, without a packet capture being useful to anyone else.
  *
  * Privacy rule enforced by construction: `DiagEvent` has no field that can carry
  * application payload. Lengths are bucketed, not exact, so even the diagnostic stream
  * does not become a side channel if it is later exported to a shared SIEM.
  */
enum DiagKind(val wire: String):
  case MessageAccepted extends DiagKind("message_accepted")
  case MessageAssembled extends DiagKind("message_assembled")
  case MessageDropped extends DiagKind("message_dropped")
  case CellSealed extends DiagKind("cell_sealed")
  case CellOpened extends DiagKind("cell_opened")
  case CellRejected extends DiagKind("cell_rejected")
  case DeadlineMiss extends DiagKind("deadline_miss")
  case KeyEpochRotated extends DiagKind("key_epoch_rotated")
  case ShaperReconfigured extends DiagKind("shaper_reconfigured")
  case LinkDegraded extends DiagKind("link_degraded")

/** Field set is fixed and payload-free. */
final case class DiagEvent(
    atNanos: Long,
    node: String,        // "bank-a" / "bank-b", never a customer identifier
    kind: DiagKind,
    msgId: Long,         // correlator; join with the business ledger, not with identities
    corrId: String,      // business correlation id, already present in the app's logs
    epoch: Long,
    seq: Long,
    cells: Int,
    /** Size bucket, not exact bytes: keeps diagnostics from leaking size to a SIEM reader. */
    sizeBucket: String,
    latencyBucket: String,
    reason: String,
    detail: String
)

object Diag:
  def sizeBucket(bytes: Long): String = bytes match
    case b if b <= 0     => "0"
    case b if b <= 256   => "le256"
    case b if b <= 1024  => "le1k"
    case b if b <= 8192  => "le8k"
    case b if b <= 65536 => "le64k"
    case _               => "gt64k"

  def latencyBucket(nanos: Long): String =
    val ms = nanos / 1_000_000.0
    if ms < 1 then "lt1ms"
    else if ms < 5 then "lt5ms"
    else if ms < 10 then "lt10ms"
    else if ms < 25 then "lt25ms"
    else if ms < 50 then "lt50ms"
    else if ms < 100 then "lt100ms"
    else if ms < 500 then "lt500ms"
    else "ge500ms"

  def accepted(now: Long, node: String, msgId: Long, corrId: String, epoch: Long, bytes: Long): DiagEvent =
    DiagEvent(now, node, DiagKind.MessageAccepted, msgId, corrId, epoch, -1, 0,
      sizeBucket(bytes), "-", "", "")

  def cellSealed(now: Long, node: String, epoch: Long, seq: Long, cells: Int, cover: Boolean): DiagEvent =
    DiagEvent(now, node, DiagKind.CellSealed, -1, "", epoch, seq, cells,
      "-", "-", if cover then "cover" else "data", "")

  def cellOpened(now: Long, node: String, epoch: Long, seq: Long, cells: Int, records: Int): DiagEvent =
    DiagEvent(now, node, DiagKind.CellOpened, -1, "", epoch, seq, cells,
      "-", "-", s"records=$records", "")

  def rejected(now: Long, node: String, epoch: Long, seq: Long, reason: String): DiagEvent =
    DiagEvent(now, node, DiagKind.CellRejected, -1, "", epoch, seq, 0, "-", "-", reason, "")

  def assembled(now: Long, node: String, msgId: Long, corrId: String, epoch: Long, bytes: Long, latency: Long, cells: Int): DiagEvent =
    DiagEvent(now, node, DiagKind.MessageAssembled, msgId, corrId, epoch, -1, cells,
      sizeBucket(bytes), latencyBucket(latency), "", "")

  def deadlineMiss(now: Long, node: String, msgId: Long, epoch: Long, latency: Long): DiagEvent =
    DiagEvent(now, node, DiagKind.DeadlineMiss, msgId, "", epoch, -1, 0,
      "-", latencyBucket(latency), "hold_exceeded", "")

/** Collects diagnostics and renders them in logfmt so they drop straight into existing
  * log pipelines. A sink is pluggable: file, SIEM, or an in-band diagnostic stream. */
trait DiagSink:
  def emit(e: DiagEvent): Unit

final class InMemoryDiagSink(limit: Int = 200_000) extends DiagSink:
  private val buf = scala.collection.mutable.ArrayBuffer.empty[DiagEvent]
  var dropped: Long = 0L
  def emit(e: DiagEvent): Unit =
    if buf.length < limit then buf += e else dropped += 1
  def events: Vector[DiagEvent] = buf.toVector
  def count(kind: DiagKind): Int = buf.count(_.kind == kind)

object LogfmtDiagSink:
  def render(e: DiagEvent): String =
    def q(s: String): String =
      if s.isEmpty then "\"\""
      else if s.exists(c => c == ' ' || c == '=' || c == '"') then "\"" + s.replace("\"", "\\\"") + "\""
      else s
    Seq(
      "ts_ns" -> e.atNanos.toString,
      "node" -> q(e.node),
      "kind" -> e.kind.wire,
      "msg_id" -> e.msgId.toString,
      "corr_id" -> q(e.corrId),
      "epoch" -> e.epoch.toString,
      "seq" -> e.seq.toString,
      "cells" -> e.cells.toString,
      "size_bucket" -> e.sizeBucket,
      "latency_bucket" -> e.latencyBucket,
      "reason" -> q(e.reason),
      "detail" -> q(e.detail)
    ).map((k, v) => s"$k=$v").mkString(" ")
