from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path


def plot_results(input_csv: Path, output_dir: Path) -> list[Path]:
    if not input_csv.exists():
        raise FileNotFoundError(f"result file not found: {input_csv}")

    rows = read_rows(input_csv)
    output_dir.mkdir(parents=True, exist_ok=True)

    outputs = [
        output_dir / "can_fuzzing_coverage.pdf",
        output_dir / "can_fuzzing_reasons.pdf",
        output_dir / "can_fuzzing_frame_mix.pdf",
    ]

    write_trend_pdf(rows, outputs[0])
    write_reasons_pdf(rows, outputs[1])
    write_frame_mix_pdf(rows, outputs[2])
    return outputs


def read_rows(input_csv: Path) -> list[dict[str, str]]:
    with input_csv.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_trend_pdf(rows: list[dict[str, str]], output: Path) -> None:
    width, height = 640, 390
    canvas = PDFCanvas(width, height)
    canvas.text(60, 360, "CAN fuzzing coverage and cumulative faults", 14)
    canvas.line(55, 55, 585, 55)
    canvas.line(55, 55, 55, 330)
    canvas.text(270, 25, "Test case", 10)
    canvas.text(30, 338, "Count", 10)

    if rows:
        xs = [int(row["case_id"]) for row in rows]
        coverage = [int(row["coverage_count"]) for row in rows]
        faults = cumulative_sum(int(row["fault"]) for row in rows)
        max_x = max(xs) or 1
        max_y = max(max(coverage, default=0), max(faults, default=0), 1)
        cov_points = [(55 + x / max_x * 530, 55 + y / max_y * 260) for x, y in zip(xs, coverage)]
        fault_points = [(55 + x / max_x * 530, 55 + y / max_y * 260) for x, y in zip(xs, faults)]
        canvas.polyline(cov_points, "0 0.28 0.65", 1.8)
        canvas.polyline(fault_points, "0.75 0.1 0.1", 1.6)
        canvas.text(420, 330, "Coverage points", 10, "0 0.28 0.65")
        canvas.text(420, 312, "Cumulative faults", 10, "0.75 0.1 0.1")
        canvas.text(55, 40, str(min(xs)), 8)
        canvas.text(560, 40, str(max(xs)), 8)
        canvas.text(25, 55, "0", 8)
        canvas.text(20, 315, str(max_y), 8)

    canvas.write(output)


def write_reasons_pdf(rows: list[dict[str, str]], output: Path) -> None:
    width, height = 640, 390
    canvas = PDFCanvas(width, height)
    canvas.text(60, 360, "Top CAN fuzzing observation reasons", 14)
    counts = Counter(row["reason"] for row in rows)
    items = counts.most_common(8)
    max_value = max((value for _, value in items), default=1)
    y = 315
    for label, value in items:
        bar_width = 390 * value / max_value
        canvas.text(60, y + 4, label.replace("_", " ")[:28], 9)
        canvas.rect(260, y, bar_width, 13, "0.20 0.45 0.70")
        canvas.text(260 + bar_width + 8, y + 3, str(value), 9)
        y -= 30
    canvas.write(output)


def write_frame_mix_pdf(rows: list[dict[str, str]], output: Path) -> None:
    width, height = 360, 290
    canvas = PDFCanvas(width, height)
    canvas.text(35, 260, "Frame format and type mix", 13)
    format_counts = Counter(row["frame_format"] for row in rows)
    type_counts = Counter(row["frame_type"] for row in rows)
    items = [
        ("standard", format_counts["standard"], "0.20 0.60 0.58"),
        ("extended", format_counts["extended"], "0.30 0.55 0.25"),
        ("data", type_counts["data"], "0.90 0.45 0.10"),
        ("remote", type_counts["remote"], "0.85 0.20 0.20"),
        ("error", type_counts["error"], "0.55 0.35 0.65"),
    ]
    max_value = max((value for _, value, _ in items), default=1)
    x = 45
    for label, value, color in items:
        height_value = 165 * value / max_value
        canvas.rect(x, 55, 32, height_value, color)
        canvas.text(x - 6, 38, label, 8)
        canvas.text(x, 58 + height_value, str(value), 8)
        x += 58
    canvas.line(35, 55, 330, 55)
    canvas.line(35, 55, 35, 230)
    canvas.write(output)


def cumulative_sum(values) -> list[int]:
    total = 0
    result: list[int] = []
    for value in values:
        total += value
        result.append(total)
    return result


class PDFCanvas:
    def __init__(self, width: int, height: int) -> None:
        self.width = width
        self.height = height
        self.commands: list[str] = []

    def text(self, x: float, y: float, value: str, size: int = 10, color: str = "0 0 0") -> None:
        escaped = value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        self.commands.append(f"BT /F1 {size} Tf {color} rg {x:.2f} {y:.2f} Td ({escaped}) Tj ET")

    def line(self, x1: float, y1: float, x2: float, y2: float, color: str = "0 0 0", width: float = 1.0) -> None:
        self.commands.append(f"{color} RG {width:.2f} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def rect(self, x: float, y: float, width: float, height: float, color: str) -> None:
        self.commands.append(f"{color} rg {x:.2f} {y:.2f} {width:.2f} {height:.2f} re f")

    def polyline(self, points: list[tuple[float, float]], color: str, width: float) -> None:
        if len(points) < 2:
            return
        first_x, first_y = points[0]
        parts = [f"{color} RG {width:.2f} w {first_x:.2f} {first_y:.2f} m"]
        for x, y in points[1:]:
            parts.append(f"{x:.2f} {y:.2f} l")
        parts.append("S")
        self.commands.append(" ".join(parts))

    def write(self, output: Path) -> None:
        stream = "\n".join(self.commands).encode("latin-1", errors="replace")
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.width} {self.height}] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".encode("ascii"),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
        ]
        data = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(data))
            data.extend(f"{index} 0 obj\n".encode("ascii"))
            data.extend(obj)
            data.extend(b"\nendobj\n")
        xref_offset = len(data)
        data.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        data.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            data.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        data.extend(f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
        output.write_bytes(data)
