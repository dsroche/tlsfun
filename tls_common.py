"""Common imports and classes across the various pieces of TLS code."""

from typing import Any, override, Protocol, Self, runtime_checkable
from collections.abc import Iterable, Mapping, Callable
from abc import ABC, abstractmethod, abstractproperty
from functools import cached_property
from dataclasses import dataclass, field

import logging
logger = logging.getLogger('tlsfun')

class TlsError(RuntimeError):
    pass

class TlsTODO(TlsError):
    pass
