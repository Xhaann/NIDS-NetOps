from datetime import datetime, timezone
from typing import Iterable, Iterator, Optional

from capture.packet_observation import CaptureSource, LinkType, PacketObservation
from capture.packet_source import CaptureError


class IterablePacketSource:
    def __init__(
        self,
        records: Iterable[bytes],
        *,
        source: CaptureSource = CaptureSource("local-iterable"),
        link_type: Optional[LinkType] = None,
    ) -> None:
        if not isinstance(source, CaptureSource):
            raise TypeError("source must be a CaptureSource")
        if link_type is not None and not isinstance(link_type, LinkType):
            raise TypeError("link_type must be a LinkType or None")
        self._records = records
        self._source = source
        self._link_type = link_type
        self._iterator: Optional[Iterator[bytes]] = None
        self._started = False
        self._stopped = False
        self._failed = False

    def start(self) -> None:
        if self._started or self._stopped:
            raise RuntimeError("source cannot be restarted")
        self._started = True
        try:
            self._iterator = iter(self._records)
        except OSError as error:
            self._failed = True
            raise CaptureError("packet source could not start") from error
        except Exception:
            self._failed = True
            raise
        finally:
            self._records = ()

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
        if self._iterator is None:
            raise StopIteration
        try:
            raw_bytes = next(self._iterator)
        except StopIteration:
            self._iterator = None
            raise
        except OSError as error:
            self._failed = True
            raise CaptureError("packet acquisition failed") from error
        except Exception:
            self._failed = True
            raise
        if not isinstance(raw_bytes, bytes):
            self._failed = True
            raise TypeError("raw_bytes must be immutable bytes")
        return PacketObservation(
            captured_at=datetime.now(timezone.utc),
            link_type=self._link_type,
            captured_length=len(raw_bytes),
            original_length=len(raw_bytes),
            raw_bytes=raw_bytes,
            source=self._source,
        )

    def stop(self) -> None:
        self._stopped = True
        self._iterator = None
        self._records = ()
