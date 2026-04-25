"""
LicenseSeal Watermark Module
=============================
Provides invisible code watermarking using steganography and semantic patterns.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

# Zero-width characters for steganography
ZWC_INVISIBLE = [
    "\u200B",  # Zero Width Space
    "\u200C",  # Zero Width Non-Joiner
    "\u200D",  # Zero Width Joiner
    "\u200E",  # Left-To-Right Mark
    "\u200F",  # Right-To-Left Mark
    "\uFEFF",  # Byte Order Mark
]

# Mapping for binary encoding
ZWC_MAP = {0: "\u200B", 1: "\u200C", 2: "\u200D", 3: "\u200E"}


@dataclass
class WatermarkConfig:
    """Configuration for watermark embedding."""
    enabled: bool = True
    strength: int = 3  # How many times to embed the watermark
    use_zwc: bool = True  # Use zero-width characters
    use_ast: bool = True  # Use AST-based semantic watermarks
    use_honey_logic: bool = True  # Embed functional, project-specific honey logic snippets
    honey_density: int = 1  # Helper snippets per Python file
    project_id: str = ""


@dataclass(frozen=True)
class HoneyLogicFingerprint:
    """AST-level fingerprint for a honey-logic micro-snippet."""
    fingerprint: str
    function: str
    constants: list[int]
    operators: list[str]
    shape: str
    rarity_score: float = 1.0


class HoneyLogicGenerator:
    """
    Generates tiny, functionally correct Python helpers whose AST shape and
    integer-constant vector are deterministically derived from project metadata.

    The name is intentionally low value; detection is based on AST structure,
    constants and operator sequences so simple renames do not erase the signal.
    """

    PRIME_POOL = [
        1009, 2017, 3253, 4099, 6521, 8191, 12289, 16381,
        32749, 65521, 131071, 262147, 524287, 1048583,
    ]

    def __init__(self, project_id: str, signature: str):
        material = f"{project_id}:{signature}".encode("utf-8", "surrogatepass")
        self.digest = hashlib.sha256(material).digest()

    def helper_name(self, ordinal: int = 0) -> str:
        h = hashlib.sha256(self.digest + bytes([ordinal & 0xFF])).hexdigest()
        return f"_ls_fold_{h[:10]}"

    def helper_source(self, ordinal: int = 0) -> str:
        """Return one project-specific honey-logic helper function."""
        local = hashlib.sha256(self.digest + b":helper:" + bytes([ordinal & 0xFF])).digest()
        a = self.PRIME_POOL[local[0] % len(self.PRIME_POOL)]
        b = self.PRIME_POOL[local[1] % len(self.PRIME_POOL)]
        c = self.PRIME_POOL[local[2] % len(self.PRIME_POOL)]
        shift_a = 3 + (local[3] % 11)
        shift_b = 5 + (local[4] % 13)
        width = 9 + (local[5] % 8)
        mask = (1 << width) - 1
        salt = int.from_bytes(local[6:10], "big") & mask
        name = self.helper_name(ordinal)

        return f"""
def {name}(n: int) -> int:
    \"\"\"Internal normalization helper.\"\"\"
    n = int(n)
    x = ((n * {a}) ^ (n >> {shift_a})) & {mask}
    y = ((x + {b}) * {c}) ^ (x << {shift_b})
    return (y ^ {salt}) & {mask}
"""

    def expected_fingerprints(self, density: int = 1) -> list[HoneyLogicFingerprint]:
        detector = HoneyLogicDetector()
        fps: list[HoneyLogicFingerprint] = []
        for ordinal in range(max(1, density)):
            fps.extend(detector.extract_fingerprints(self.helper_source(ordinal)))
        return fps


class HoneyLogicDetector:
    """
    Extracts robust honey-logic fingerprints from Python source.

    Exact matches compare the digest of AST shape + integer constants + operator
    sequence. Fuzzy callers can use the exposed features for partial scoring.
    """

    def extract_fingerprints(self, source: str) -> list[HoneyLogicFingerprint]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        results: list[HoneyLogicFingerprint] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue

            constants: list[int] = []
            operators: list[str] = []
            for child in ast.walk(node):
                if isinstance(child, ast.Constant) and isinstance(child.value, int):
                    constants.append(int(child.value))
                elif isinstance(child, ast.BinOp):
                    operators.append(type(child.op).__name__)

            # Avoid fingerprinting trivial ordinary functions.
            if len(constants) < 3 or len(operators) < 4:
                continue

            shape = self._shape(node)
            raw = {
                "constants": sorted(constants),
                "operators": operators,
                "shape": shape,
            }
            fingerprint = hashlib.sha256(
                json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()

            rarity = min(1.0, 0.35 + (len(set(constants)) * 0.07) + (len(set(operators)) * 0.06))
            results.append(HoneyLogicFingerprint(
                fingerprint=fingerprint,
                function=node.name,
                constants=sorted(constants),
                operators=operators,
                shape=shape,
                rarity_score=rarity,
            ))

        return results

    def _shape(self, node: ast.AST) -> str:
        names: list[str] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.append("Name")
            elif isinstance(child, ast.arg):
                names.append("arg")
            elif isinstance(child, ast.Constant):
                names.append("Const")
            else:
                names.append(type(child).__name__)
        return "/".join(names[:96])

    def fuzzy_similarity(
        self,
        observed: HoneyLogicFingerprint,
        expected: HoneyLogicFingerprint,
    ) -> float:
        """Feature-level similarity for renamed or lightly edited snippets."""
        observed_constants = set(observed.constants)
        expected_constants = set(expected.constants)
        if observed_constants or expected_constants:
            const_score = len(observed_constants & expected_constants) / len(observed_constants | expected_constants)
        else:
            const_score = 0.0

        observed_ops = set(observed.operators)
        expected_ops = set(expected.operators)
        if observed_ops or expected_ops:
            op_score = len(observed_ops & expected_ops) / len(observed_ops | expected_ops)
        else:
            op_score = 0.0

        shape_score = 1.0 if observed.shape == expected.shape else self._prefix_similarity(observed.shape, expected.shape)
        return (0.55 * const_score) + (0.25 * op_score) + (0.20 * shape_score)

    def _prefix_similarity(self, a: str, b: str) -> float:
        left = a.split("/")
        right = b.split("/")
        max_len = max(len(left), len(right), 1)
        same = 0
        for x, y in zip(left, right):
            if x == y:
                same += 1
            else:
                break
        return same / max_len


def embed_honey_logic(
    source: str,
    project_id: str,
    signature: str,
    density: int = 1,
) -> str:
    """Append deterministic honey-logic helpers to Python source code."""
    if "def _ls_fold_" in source:
        return source

    generator = HoneyLogicGenerator(project_id, signature)
    snippets = [generator.helper_source(i).rstrip() for i in range(max(1, density))]
    suffix = "\n\n# LicenseSeal internal normalization sentinels\n" + "\n\n".join(snippets) + "\n"
    if source.endswith("\n"):
        return source + suffix
    return source + "\n" + suffix


def extract_honey_logic_fingerprints(source: str) -> list[HoneyLogicFingerprint]:
    """Extract honey-logic style fingerprints from Python source."""
    return HoneyLogicDetector().extract_fingerprints(source)


def expected_honey_logic_fingerprints(
    project_id: str,
    signature: str,
    density: int = 1,
) -> list[HoneyLogicFingerprint]:
    """Build expected honey-logic fingerprints for a protected project."""
    return HoneyLogicGenerator(project_id, signature).expected_fingerprints(density=density)



class WatermarkEncoder:
    """Encodes invisible watermarks into source code."""

    def __init__(self, config: WatermarkConfig):
        self.config = config

    def encode_message(self, message: str) -> str:
        """
        Encode a message into zero-width characters.
        Uses 2 bits per character for compact representation.
        """
        if not self.config.use_zwc:
            return message

        # Convert message to binary
        binary = ""
        for char in message:
            # Use 8 bits per character for byte-aligned decoding
            binary += format(ord(char) & 0xFF, '08b')

        # Pad to multiple of 2
        while len(binary) % 2 != 0:
            binary += "0"

        # Encode binary as ZWC sequence
        zwc_sequence = ""
        for i in range(0, len(binary), 2):
            bits = int(binary[i:i+2], 2)
            zwc_sequence += ZWC_MAP[bits]

        return zwc_sequence

    def decode_message(self, text: str) -> Optional[str]:
        """Decode a message from zero-width characters."""
        if not self.config.use_zwc:
            return None

        # Extract ZWC characters
        zwc_chars = ""
        for char in text:
            if char in ZWC_MAP.values():
                zwc_chars += char
            elif char in ZWC_MAP:
                # Also accept raw ZWC characters
                zwc_chars += char

        if len(zwc_chars) < 4:
            return None

        # Convert ZWC to binary
        binary = ""
        for char in zwc_chars:
            for bits, zwc in ZWC_MAP.items():
                if char == zwc:
                    binary += format(bits, '02b')
                    break

        # Convert binary to text
        message = ""
        for i in range(0, len(binary), 8):
            if i + 8 <= len(binary):
                byte = binary[i:i+8]
                char_code = int(byte, 2)
                if char_code > 0:
                    message += chr(char_code)

        return message

    def embed_zwc_watermark(self, source: str, project_id: str, signature: str) -> str:
        """
        Embed watermark using zero-width characters.
        Embeds at line endings and in strings.
        """
        if not self.config.use_zwc:
            return source

        # Create watermark payload
        payload = f"{project_id}:{signature}"
        encoded = self.encode_message(payload)

        # Embed multiple times for redundancy
        lines = source.splitlines()
        embed_count = min(self.config.strength, len(lines))

        # Distribute watermarks across the file
        step = max(1, len(lines) // embed_count)
        for i in range(0, embed_count):
            idx = (i * step) % len(lines) if lines else 0
            if idx < len(lines):
                # Add watermark at end of line (invisible in most editors)
                lines[idx] = lines[idx] + encoded

        return "\n".join(lines)

    def embed_semantic_watermark(self, source: str, project_id: str, signature: str) -> str:
        """
        Embed watermark using AST-level semantic patterns.
        These are structural changes that don't affect functionality.
        """
        if not self.config.use_ast:
            return source

        # Generate hash-based pattern seed
        seed = int(hashlib.sha256(f"{project_id}:{signature}".encode()).hexdigest()[:8], 16)

        # Apply semantic watermarks based on language
        result = source

        # Pattern 1: Swap independent boolean operands (Python)
        if " and " in result or " or " in result:
            # Use seed to determine swap pattern
            if seed % 3 == 0:
                # Swap "and" -> "and" (no change, but marks the pattern)
                pass
            elif seed % 3 == 1:
                # Add redundant parentheses
                result = re.sub(r'(\w+\s+and\s+\w+)', r'(\1)', result)

        # Pattern 2: Add harmless comments with encoded info
        comment_watermark = f"/*w:{project_id[:8]}*/"
        if seed % 2 == 0 and "//" in source:
            # Insert at first comment position
            result = re.sub(r'(//)', f'//{comment_watermark}', result, count=1)

        # Pattern 3: String literal watermarks (for languages with strings)
        if '"' in source or "'" in source:
            # Inject into a harmless string
            marker = f"\\x{seed % 256:02x}"
            result = re.sub(r'(".*?")', f'\\1{marker}', result, count=1)

        return result


class WatermarkDecoder:
    """Decodes invisible watermarks from source code."""

    def __init__(self, config: WatermarkConfig):
        self.config = config

    def detect_zwc_watermark(self, source: str) -> Optional[dict]:
        """Detect zero-width character watermarks."""
        if not self.config.use_zwc:
            return None

        encoder = WatermarkEncoder(self.config)
        decoded = encoder.decode_message(source)

        if decoded and ":" in decoded:
            parts = decoded.split(":", 1)
            return {
                "project_id": parts[0],
                "signature": parts[1] if len(parts) > 1 else "",
                "method": "zwc",
            }

        return None

    def detect_semantic_watermark(self, source: str) -> Optional[dict]:
        """Detect semantic pattern watermarks."""
        if not self.config.use_ast:
            return None

        # Look for known patterns
        patterns = [
            (r'/\*w:([a-f0-9]{8})\*/', "block_comment"),
            (r'//w:([a-f0-9]{8})', "line_comment"),
            (r'\\x([0-9a-f]{2})', "string_escape"),
        ]

        for pattern, pattern_type in patterns:
            match = re.search(pattern, source)
            if match:
                return {
                    "project_id": match.group(1),
                    "signature": "",
                    "method": "semantic",
                    "pattern_type": pattern_type,
                }

        return None

    def extract_watermark(self, source: str) -> Optional[dict]:
        """Extract any watermark from source code."""
        # Try ZWC first (more stealthy)
        zwc_result = self.detect_zwc_watermark(source)
        if zwc_result:
            return zwc_result

        # Fall back to semantic patterns
        semantic_result = self.detect_semantic_watermark(source)
        if semantic_result:
            return semantic_result

        return None


def embed_watermark(
    source: str,
    project_id: str,
    signature: str,
    config: WatermarkConfig | None = None,
) -> str:
    """Main function to embed a watermark."""
    cfg = config or WatermarkConfig(project_id=project_id)
    encoder = WatermarkEncoder(cfg)

    result = source

    # Apply ZWC watermark
    if cfg.use_zwc:
        result = encoder.embed_zwc_watermark(result, project_id, signature)

    # Apply semantic watermark
    if cfg.use_ast:
        result = encoder.embed_semantic_watermark(result, project_id, signature)

    # Apply executable honey-logic only to Python modules.
    if cfg.use_honey_logic:
        result = embed_honey_logic(result, project_id, signature, cfg.honey_density)

    return result


def extract_watermark(
    source: str,
    config: WatermarkConfig | None = None,
) -> Optional[dict]:
    """Main function to extract a watermark."""
    cfg = config or WatermarkConfig()
    decoder = WatermarkDecoder(cfg)
    return decoder.extract_watermark(source)


def has_watermark(source: str, config: WatermarkConfig | None = None) -> bool:
    """Check if source contains any watermark."""
    return extract_watermark(source, config) is not None


# Watermark strength levels
class WatermarkStrength:
    """Predefined watermark strength levels."""
    MINIMAL = WatermarkConfig(enabled=True, strength=1, use_zwc=True, use_ast=False)
    STANDARD = WatermarkConfig(enabled=True, strength=3, use_zwc=True, use_ast=True)
    ROBUST = WatermarkConfig(enabled=True, strength=5, use_zwc=True, use_ast=True)


def create_watermark_config(
    project_id: str,
    strength: str = "standard",
) -> WatermarkConfig:
    """Factory function to create watermark config."""
    strength_map = {
        "minimal": WatermarkStrength.MINIMAL,
        "standard": WatermarkStrength.STANDARD,
        "robust": WatermarkStrength.ROBUST,
    }
    config = strength_map.get(strength, WatermarkStrength.STANDARD)
    config.project_id = project_id
    return config


# Watermark verification
def verify_watermark(
    source: str,
    expected_project_id: str,
    config: WatermarkConfig | None = None,
) -> bool:
    """Verify that source contains a specific project's watermark."""
    watermark = extract_watermark(source, config)
    if not watermark:
        return False
    return watermark.get("project_id", "").startswith(expected_project_id[:8])


# Batch watermark operations
def watermark_project_files(
    files: Iterable[Path],
    project_id: str,
    signature: str,
    config: WatermarkConfig | None = None,
) -> dict[Path, bool]:
    """Watermark multiple files in a project."""
    cfg = config or WatermarkConfig(project_id=project_id)
    results = {}

    for path in files:
        try:
            original = path.read_text(encoding="utf-8")
            file_cfg = cfg
            if path.suffix != ".py" and cfg.use_honey_logic:
                file_cfg = WatermarkConfig(
                    enabled=cfg.enabled,
                    strength=cfg.strength,
                    use_zwc=cfg.use_zwc,
                    use_ast=cfg.use_ast,
                    use_honey_logic=False,
                    honey_density=cfg.honey_density,
                    project_id=cfg.project_id,
                )
            watermarked = embed_watermark(original, project_id, signature, file_cfg)
            path.write_text(watermarked, encoding="utf-8")
            results[path] = True
        except Exception:
            results[path] = False

    return results


def scan_for_watermarks(
    files: Iterable[Path],
    config: WatermarkConfig | None = None,
) -> dict[Path, dict | None]:
    """Scan multiple files for watermarks."""
    results = {}

    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
            results[path] = extract_watermark(source, config)
        except Exception:
            results[path] = None

    return results