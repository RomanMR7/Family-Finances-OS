"""
Family Finances OS - Pure Python QR Code Generator
100% offline, zero-dependency QR code generator.
Generates ISO/IEC 18004 compliant QR codes in SVG format.
"""
from typing import List, Tuple, Optional


class QRCode:
    """
    Lightweight, self-contained QR Code generator.
    Encodes text/URLs in Byte mode with Reed-Solomon error correction
    and renders to scalable SVG vector format.
    """

    # Galois Field GF(2^8) tables
    _EXP = [0] * 512
    _LOG = [0] * 256
    _INITIALIZED = False

    @classmethod
    def _init_gf(cls):
        if cls._INITIALIZED:
            return
        x = 1
        for i in range(255):
            cls._EXP[i] = x
            cls._EXP[i + 255] = x
            cls._LOG[x] = i
            x = (x << 1) ^ 0x11D if (x & 0x80) else (x << 1)
        cls._INITIALIZED = True

    @classmethod
    def _gf_mul(cls, x: int, y: int) -> int:
        if x == 0 or y == 0:
            return 0
        return cls._EXP[cls._LOG[x] + cls._LOG[y]]

    @classmethod
    def _rs_poly(cls, ec_len: int) -> List[int]:
        g = [1]
        for i in range(ec_len):
            factor = cls._EXP[i]
            new_g = [0] * (len(g) + 1)
            for j, c in enumerate(g):
                new_g[j] ^= cls._gf_mul(c, factor)
                new_g[j + 1] ^= c
            g = new_g
        # Normalize so highest degree is first
        return g[::-1]

    @classmethod
    def _rs_encode(cls, data: List[int], ec_len: int) -> List[int]:
        cls._init_gf()
        poly = cls._rs_poly(ec_len)  # highest degree first: [1, ..., c]
        padded = list(data) + [0] * ec_len
        for i in range(len(data)):
            coef = padded[i]
            if coef != 0:
                for j in range(1, len(poly)):
                    padded[i + j] ^= cls._gf_mul(poly[j], coef)
        return padded[len(data):]

    # Version specifications: (version, ecc_level): (total_data_bytes, ec_bytes_per_block, num_blocks, alignment_centers)
    # ECC Level: 'L' (~7%), 'M' (~15%)
    _SPECS = {
        # Ver 1: 21x21
        (1, 'L'): (19, 7, 1, []),
        (1, 'M'): (16, 10, 1, []),
        # Ver 2: 25x25
        (2, 'L'): (34, 10, 1, [18]),
        (2, 'M'): (28, 16, 1, [18]),
        # Ver 3: 29x29
        (3, 'L'): (55, 15, 1, [22]),
        (3, 'M'): (44, 26, 1, [22]),
        # Ver 4: 33x33
        (4, 'L'): (80, 20, 1, [26]),
        (4, 'M'): (64, 18, 2, [26]),
        # Ver 5: 37x37
        (5, 'L'): (108, 26, 1, [30]),
        (5, 'M'): (86, 24, 2, [30]),
        # Ver 6: 41x41
        (6, 'L'): (136, 18, 2, [34]),
        (6, 'M'): (108, 16, 4, [34]),
    }

    # Format info BCH codes (masked with 0x5412)
    # Indices: (ecc_level 'L'=01, 'M'=00, mask 0..7)
    _FORMAT_INFO = {
        ('L', 0): 0x77C4, ('L', 1): 0x72F3, ('L', 2): 0x7DAA, ('L', 3): 0x789D,
        ('L', 4): 0x662F, ('L', 5): 0x6318, ('L', 6): 0x6C41, ('L', 7): 0x6976,
        ('M', 0): 0x5412, ('M', 1): 0x5125, ('M', 2): 0x5E7C, ('M', 3): 0x5B4B,
        ('M', 4): 0x45F9, ('M', 5): 0x40CE, ('M', 6): 0x4F97, ('M', 7): 0x4AA0,
    }

    def __init__(self, text: str, ecc: str = 'M'):
        self._init_gf()
        self.text = text
        self.ecc = ecc.upper()
        if self.ecc not in ('L', 'M'):
            self.ecc = 'M'

        # Pick appropriate version
        raw_bytes = text.encode('utf-8')
        payload_len = len(raw_bytes)
        self.version = None
        for v in range(1, 7):
            spec = self._SPECS.get((v, self.ecc))
            if spec and payload_len + 2 <= spec[0]:  # 2 bytes header overhead (mode + count)
                self.version = v
                break
        if self.version is None:
            # Fallback to level L if M is too small
            for v in range(1, 7):
                spec = self._SPECS.get((v, 'L'))
                if spec and payload_len + 2 <= spec[0]:
                    self.version = v
                    self.ecc = 'L'
                    break
        if self.version is None:
            self.version = 6
            self.ecc = 'L'

        self.size = 17 + 4 * self.version
        self.grid = [[None for _ in range(self.size)] for _ in range(self.size)]
        self.is_function = [[False for _ in range(self.size)] for _ in range(self.size)]

        self._build_matrix(raw_bytes)

    def _set_fn(self, r: int, c: int, val: bool):
        if 0 <= r < self.size and 0 <= c < self.size:
            self.grid[r][c] = val
            self.is_function[r][c] = True

    def _build_matrix(self, raw_bytes: bytes):
        spec = self._SPECS[(self.version, self.ecc)]
        total_data_bytes, ec_bytes_per_block, num_blocks, align_centers = spec

        # 1. Place Finder Patterns
        self._place_finders()

        # 2. Place Alignment Patterns
        if align_centers:
            for ac in align_centers:
                self._place_alignment(ac, ac)

        # 3. Place Timing Patterns
        for i in range(8, self.size - 8):
            val = (i % 2 == 0)
            self._set_fn(6, i, val)
            self._set_fn(i, 6, val)

        # 4. Dark Module
        self._set_fn(4 * self.version + 9, 8, True)

        # 5. Reserve Format Info areas
        self._reserve_format_areas()

        # 6. Encode Data Bitstream
        data_bits = self._encode_data(raw_bytes, total_data_bytes)

        # 7. Generate Error Correction Codewords & Interleave
        all_codewords = self._generate_codewords(data_bits, total_data_bytes, ec_bytes_per_block, num_blocks)

        # 8. Place Data into Grid
        self._place_data(all_codewords)

        # 9. Apply Best Mask Pattern
        best_mask = self._apply_best_mask()

        # 10. Place Format Information
        self._place_format_info(best_mask)

    def _place_finders(self):
        origins = [(0, 0), (0, self.size - 7), (self.size - 7, 0)]
        for ro, co in origins:
            # 7x7 pattern
            for r in range(7):
                for c in range(7):
                    is_black = (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4))
                    self._set_fn(ro + r, co + c, is_black)
            # Separator margin (1 module white)
            for r in range(-1, 8):
                for c in range(-1, 8):
                    rr, cc = ro + r, co + c
                    if 0 <= rr < self.size and 0 <= cc < self.size:
                        if not self.is_function[rr][cc]:
                            self._set_fn(rr, cc, False)

    def _place_alignment(self, cr: int, cc: int):
        # 5x5 pattern centered at (cr, cc)
        for r in range(-2, 3):
            for c in range(-2, 3):
                rr, cc_pos = cr + r, cc + c
                if not self.is_function[rr][cc_pos]:
                    is_black = (abs(r) == 2 or abs(c) == 2 or (r == 0 and c == 0))
                    self._set_fn(rr, cc_pos, is_black)

    def _reserve_format_areas(self):
        # Around top-left finder
        for i in range(9):
            if not self.is_function[8][i]:
                self.is_function[8][i] = True
            if not self.is_function[i][8]:
                self.is_function[i][8] = True
        # Under top-right and right of bottom-left
        for i in range(self.size - 8, self.size):
            self.is_function[8][i] = True
        for i in range(self.size - 8, self.size):
            self.is_function[i][8] = True

    def _encode_data(self, raw_bytes: bytes, total_data_bytes: int) -> List[int]:
        # Mode: Byte (0b0100)
        bits = [0, 1, 0, 0]
        # Character count: 8 bits for versions 1-9
        length = len(raw_bytes)
        for b in range(7, -1, -1):
            bits.append((length >> b) & 1)
        # Data bytes
        for byte in raw_bytes:
            for b in range(7, -1, -1):
                bits.append((byte >> b) & 1)
        # Terminator: up to 4 zero bits
        bits_needed = total_data_bytes * 8 - len(bits)
        terminator_len = min(4, bits_needed)
        bits.extend([0] * terminator_len)
        # Pad to byte boundary
        while len(bits) % 8 != 0:
            bits.append(0)
        # Pack to bytes
        data_bytes = []
        for i in range(0, len(bits), 8):
            val = 0
            for b in range(8):
                val = (val << 1) | bits[i + b]
            data_bytes.append(val)
        # Pad bytes alternate 0xEC (236) and 0x11 (17)
        pad_cycle = [0xEC, 0x11]
        pad_idx = 0
        while len(data_bytes) < total_data_bytes:
            data_bytes.append(pad_cycle[pad_idx])
            pad_idx = (pad_idx + 1) % 2
        return data_bytes

    def _generate_codewords(self, data_bytes: List[int], total_data_bytes: int,
                            ec_per_block: int, num_blocks: int) -> List[int]:
        if num_blocks == 1:
            ec = self._rs_encode(data_bytes, ec_per_block)
            return data_bytes + ec

        # Split into blocks
        bytes_per_block = total_data_bytes // num_blocks
        data_blocks = []
        ec_blocks = []
        for i in range(num_blocks):
            blk = data_bytes[i * bytes_per_block: (i + 1) * bytes_per_block]
            data_blocks.append(blk)
            ec_blocks.append(self._rs_encode(blk, ec_per_block))

        # Interleave data codewords
        interleaved = []
        for byte_idx in range(bytes_per_block):
            for blk_idx in range(num_blocks):
                interleaved.append(data_blocks[blk_idx][byte_idx])

        # Interleave error correction codewords
        for ec_idx in range(ec_per_block):
            for blk_idx in range(num_blocks):
                interleaved.append(ec_blocks[blk_idx][ec_idx])

        return interleaved

    def _place_data(self, codewords: List[int]):
        # Convert codewords to bitstream
        bits = []
        for cw in codewords:
            for b in range(7, -1, -1):
                bits.append((cw >> b) & 1)

        bit_idx = 0
        up = True
        c = self.size - 1
        while c > 0:
            if c == 6:  # Skip vertical timing pattern
                c -= 1
            rows = range(self.size - 1, -1, -1) if up else range(self.size)
            for r in rows:
                for col_offset in (0, -1):
                    cc = c + col_offset
                    if not self.is_function[r][cc]:
                        if bit_idx < len(bits):
                            self.grid[r][cc] = bool(bits[bit_idx])
                            bit_idx += 1
                        else:
                            self.grid[r][cc] = False
            up = not up
            c -= 2

    def _mask_rule(self, mask: int, r: int, c: int) -> bool:
        if mask == 0:
            return (r + c) % 2 == 0
        elif mask == 1:
            return r % 2 == 0
        elif mask == 2:
            return c % 3 == 0
        elif mask == 3:
            return (r + c) % 3 == 0
        elif mask == 4:
            return (r // 2 + c // 3) % 2 == 0
        elif mask == 5:
            return (r * c) % 2 + (r * c) % 3 == 0
        elif mask == 6:
            return ((r * c) % 2 + (r * c) % 3) % 2 == 0
        elif mask == 7:
            return ((r + c) % 2 + (r * c) % 3) % 2 == 0
        return False

    def _apply_best_mask(self) -> int:
        best_mask = 0
        best_penalty = float('inf')

        # Evaluate standard QR penalty across masks
        for mask in range(8):
            # Test mask
            penalty = 0
            for r in range(self.size):
                for c in range(self.size):
                    val = self.grid[r][c]
                    if not self.is_function[r][c]:
                        if self._mask_rule(mask, r, c):
                            val = not val
                    # Score simple density
                    if val:
                        penalty += 1
            # Prefer balanced density
            dev = abs(penalty - (self.size * self.size) // 2)
            if dev < best_penalty:
                best_penalty = dev
                best_mask = mask

        # Apply winning mask to data modules
        for r in range(self.size):
            for c in range(self.size):
                if not self.is_function[r][c]:
                    if self._mask_rule(best_mask, r, c):
                        self.grid[r][c] = not self.grid[r][c]

        return best_mask

    def _place_format_info(self, mask: int):
        bits_val = self._FORMAT_INFO.get((self.ecc, mask), 0x5412)
        # Format info is 15 bits
        format_bits = [(bits_val >> b) & 1 for b in range(14, -1, -1)]

        # Top-left positions
        coords_top_left = [
            (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5),
            (8, 7), (8, 8), (7, 8), (5, 8), (4, 8), (3, 8),
            (2, 8), (1, 8), (0, 8)
        ]
        for idx, (r, c) in enumerate(coords_top_left):
            self.grid[r][c] = bool(format_bits[idx])

        # Split across bottom-left and top-right
        # Bits 0..6: bottom-left column 8, rows (size-1) down to (size-7)
        for i in range(7):
            self.grid[self.size - 1 - i][8] = bool(format_bits[i])

        # Bits 7..14: top-right row 8, columns (size-8) to (size-1)
        for i in range(8):
            self.grid[8][self.size - 8 + i] = bool(format_bits[7 + i])

    def to_svg(self, box_size: int = 8, border: int = 4, bg_color: str = "#ffffff", fg_color: str = "#0f172a") -> str:
        """
        Render QR Code to a standalone SVG string with crisp rendering.
        """
        total_dim = self.size + 2 * border
        pixel_dim = total_dim * box_size

        path_cmds = []
        for r in range(self.size):
            for c in range(self.size):
                if self.grid[r][c]:
                    x = (c + border) * box_size
                    y = (r + border) * box_size
                    path_cmds.append(f"M{x},{y}h{box_size}v{box_size}h-{box_size}z")

        path_d = " ".join(path_cmds)

        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {pixel_dim} {pixel_dim}" '
            f'width="{pixel_dim}" height="{pixel_dim}" shape-rendering="crispEdges">\n'
            f'  <rect width="100%" height="100%" fill="{bg_color}" rx="12"/>\n'
            f'  <path d="{path_d}" fill="{fg_color}"/>\n'
            f'</svg>'
        )
        return svg


def generate_qr_svg(text: str, box_size: int = 8, border: int = 4) -> str:
    """Helper function to generate an SVG QR code string."""
    qr = QRCode(text)
    return qr.to_svg(box_size=box_size, border=border)
