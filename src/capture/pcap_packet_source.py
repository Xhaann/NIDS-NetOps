from datetime import datetime, timedelta, timezone
import io
import os
from os import PathLike, fstat
from pathlib import Path
from stat import S_ISREG
from struct import Struct
from typing import BinaryIO, Iterator, Optional, Union

from capture.packet_observation import CaptureSource, LinkType, PacketObservation
from capture.packet_source import CaptureError


def _open_nonblocking(path: str, flags: int) -> int:
    return os.open(path, flags | getattr(os, "O_NONBLOCK", 0))


class PcapPacketSource:
    def __init__(
        self,
        path: Union[str, PathLike[str]],
        *,
        source: CaptureSource = CaptureSource("local-pcap"),
    ) -> None:
        if not isinstance(source, CaptureSource):
            raise TypeError("source must be a CaptureSource")
        self._path = Path(path)
        self._source = source
        self._file: Optional[BinaryIO] = None
        self._record_header: Optional[Struct] = None
        self._remaining = 0
        self._snaplen = 0
        self._fraction_limit = 0
        self._fraction_divisor = 1
        self._link_type: Optional[LinkType] = None
        self._started = False
        self._stopped = False
        self._failed = False

    def start(self) -> None:
        if self._started or self._stopped:
            raise RuntimeError("source cannot be restarted")
        self._started = True
        try:
            if not S_ISREG(self._path.stat().st_mode):
                raise CaptureError("PCAP source requires a regular file")
            self._file = io.open(self._path, "rb", opener=_open_nonblocking)
            metadata = fstat(self._file.fileno())
            if not S_ISREG(metadata.st_mode):
                raise CaptureError("PCAP source requires a regular file")
            self._remaining = metadata.st_size
            header = self._read_exact(24, "global header")
            formats = {
                b"\xd4\xc3\xb2\xa1": ("<", 1000000, 1),
                b"\xa1\xb2\xc3\xd4": (">", 1000000, 1),
                b"\x4d\x3c\xb2\xa1": ("<", 1000000000, 1000),
                b"\xa1\xb2\x3c\x4d": (">", 1000000000, 1000),
            }
            if header[:4] not in formats:
                raise CaptureError("unsupported PCAP magic number")
            byte_order, self._fraction_limit, self._fraction_divisor = formats[header[:4]]
            major, minor, reserved_timezone, reserved_sigfigs, snaplen, network = Struct(
                byte_order + "HHiIII"
            ).unpack(header[4:])
            if (major, minor) != (2, 4):
                raise CaptureError("PCAP version must be 2.4")
            if snaplen == 0:
                raise CaptureError("PCAP snaplen must be positive")
            if network > 65535:
                raise CaptureError("PCAP additional link-type information is unsupported")
            self._snaplen = snaplen
            self._link_type = LinkType(network)
            self._record_header = Struct(byte_order + "IIII")
        except OSError as error:
            self._failed = True
            raise CaptureError("PCAP source could not start") from error
        except BaseException:
            self._failed = True
            raise

    def __iter__(self) -> Iterator[PacketObservation]:
        if not self._stopped:
            if not self._started:
                raise RuntimeError("source has not been started")
            if self._failed:
                raise RuntimeError("failed source must be stopped")
        return self

    def __next__(self) -> PacketObservation:
        if self._stopped:
            raise StopIteration
        if not self._started:
            raise RuntimeError("source has not been started")
        if self._failed:
            raise RuntimeError("failed source must be stopped")
        if self._remaining == 0:
            raise StopIteration
        try:
            header = self._read_exact(16, "record header")
            seconds, fraction, captured_length, original_length = self._record_header.unpack(header)
            if fraction >= self._fraction_limit:
                raise CaptureError("PCAP timestamp fraction exceeds its resolution")
            if captured_length > self._snaplen:
                raise CaptureError("PCAP captured length exceeds snaplen")
            if original_length < captured_length:
                raise CaptureError("PCAP original length is smaller than captured length")
            raw_bytes = self._read_exact(captured_length, "packet payload")
            captured_at = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                seconds=seconds, microseconds=fraction // self._fraction_divisor
            )
            return PacketObservation(
                captured_at=captured_at,
                link_type=self._link_type,
                captured_length=captured_length,
                original_length=original_length,
                raw_bytes=raw_bytes,
                source=self._source,
            )
        except OSError as error:
            self._failed = True
            raise CaptureError("PCAP packet acquisition failed") from error
        except BaseException:
            self._failed = True
            raise

    def _read_exact(self, length: int, field: str) -> bytes:
        if length > self._remaining:
            raise CaptureError(f"truncated PCAP {field}")
        data = self._file.read(length)
        if len(data) != length:
            raise CaptureError(f"truncated PCAP {field}")
        self._remaining -= length
        return data

    def stop(self) -> None:
        self._stopped = True
        handle = self._file
        self._file = None
        self._record_header = None
        self._link_type = None
        self._remaining = 0
        try:
            if handle is not None:
                handle.close()
        except OSError as error:
            raise CaptureError("PCAP source could not stop") from error
