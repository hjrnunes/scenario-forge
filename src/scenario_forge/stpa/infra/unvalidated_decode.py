"""Policy-free unvalidated construction of Pydantic model graphs.

Omitted required fields receive type-appropriate sentinels so attribute
access is safe.  Declared defaults stay authoritative.  Required nested
models are not fabricated.  Field names are ignored: sentinels depend
only on annotations.  Content validity belongs to model validators.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, TypeVar, Union, get_args, get_origin

from pydantic import BaseModel

_T = TypeVar("_T", bound=BaseModel)
_UNION_TYPE = type(int | str)
_EMPTY_COLLECTION_FACTORIES = {
    list: list,
    tuple: tuple,
    set: set,
    dict: dict,
}


def _construct_collection(
    value: Any,
    origin: Any,
    args: tuple[Any, ...],
) -> Any:
    """Construct a supported collection while preserving its element values."""
    item_type = args[0] if args else Any
    converted = [
        _construct_unvalidated(item, item_type)
        for item in value
    ]
    if origin is tuple:
        return tuple(converted)
    if origin is set:
        return set(converted)
    return converted


def _construct_union(value: Any, candidates: tuple[Any, ...]) -> Any:
    """Construct the first union member that accepts *value*."""
    for candidate in candidates:
        if candidate is type(None):
            continue
        try:
            return _construct_unvalidated(value, candidate)
        except (TypeError, ValueError):
            continue
    return value


def _construct_enum(value: Any, annotation: type[Enum]) -> Any:
    """Convert an enum value, retaining malformed values for later validation."""
    try:
        return annotation(value)
    except ValueError:
        return value


def _required_union_sentinel(candidates: tuple[Any, ...]) -> Any:
    """Choose a sentinel from a required union annotation."""
    if type(None) in candidates:
        return None
    first_member = next(
        (member for member in candidates if member is not type(None)),
        None,
    )
    return _required_field_sentinel(first_member)


def _required_collection_sentinel(origin: Any, annotation: Any) -> Any:
    """Return a fresh empty value for a supported collection annotation."""
    factory = _EMPTY_COLLECTION_FACTORIES.get(origin or annotation)
    return factory() if factory else None


def _required_scalar_sentinel(annotation: Any) -> Any:
    """Return the scalar sentinel for an omitted required field."""
    if annotation is str:
        return ""
    if annotation is int:
        return 0
    if annotation is float:
        return 0.0
    if annotation is bool:
        return False
    return None


def _required_field_sentinel(annotation: Any) -> Any:
    """Return an attribute-safe sentinel for an omitted required field."""
    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin in (_UNION_TYPE, Union):
        return _required_union_sentinel(args)

    if origin is Annotated:
        return _required_field_sentinel(args[0]) if args else None

    collection_sentinel = _required_collection_sentinel(origin, annotation)
    if collection_sentinel is not None:
        return collection_sentinel
    return _required_scalar_sentinel(annotation)


def _construct_model_values(
    value: dict[str, Any],
    annotation: type[BaseModel],
) -> dict[str, Any]:
    """Construct supplied fields and sentinels for required omitted fields."""
    values: dict[str, Any] = {}
    for name, field in annotation.model_fields.items():
        if name in value:
            values[name] = _construct_unvalidated(value[name], field.annotation)
        elif field.is_required():
            values[name] = _required_field_sentinel(field.annotation)
    return values


def construct_model_unvalidated(
    value: dict[str, Any],
    model_class: type[_T],
) -> _T:
    """Build *model_class* from a mapping without running field validators."""
    values = _construct_model_values(value, model_class)
    return model_class.model_construct(**values)


def _construct_model(value: dict[str, Any], annotation: type[BaseModel]) -> Any:
    """Construct a nested model without running field validators."""
    return construct_model_unvalidated(value, annotation)


def _construct_typed_value(value: Any, annotation: type[Any]) -> Any:
    """Construct enum or model annotations without running validators."""
    if issubclass(annotation, Enum):
        return _construct_enum(value, annotation)
    if issubclass(annotation, BaseModel) and isinstance(value, dict):
        return _construct_model(value, annotation)
    return value


def _construct_unvalidated(value: Any, annotation: Any) -> Any:
    """Construct nested Pydantic models without running field validators."""
    if value is None:
        return None

    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in (list, tuple, set):
        return _construct_collection(value, origin, args)
    if origin in (_UNION_TYPE, Union):
        return _construct_union(value, args)
    if isinstance(annotation, type):
        return _construct_typed_value(value, annotation)
    return value


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-13T19:27:54Z","module_hash":"42b61d0864d36430bd6ee61052c23708156d58146cedcdcdd20c75c1e0581383","functions":[{"id":"func/_construct_collection","name":"_construct_collection","line":26,"end_line":41,"hash":"487e61c7b0b3311307ba542df553f3530cf308e0fc05b5f89beae1029e663825"},{"id":"func/_construct_union","name":"_construct_union","line":44,"end_line":53,"hash":"ce99f4f4109b21cc72fedec293bbf589f729ae8056fca750969e103684421672"},{"id":"func/_construct_enum","name":"_construct_enum","line":56,"end_line":61,"hash":"f4db6107eb408b10149013e88bb26be525a760a5d3b7e3f38bb7db5ed121ab9c"},{"id":"func/_required_union_sentinel","name":"_required_union_sentinel","line":64,"end_line":72,"hash":"82053ad268f3a713a83ebb669d7ebfd6a2d1664b205e8692ee951ac5c74760fd"},{"id":"func/_required_collection_sentinel","name":"_required_collection_sentinel","line":75,"end_line":78,"hash":"d6730198edfe0030836c2969ca3934e2e4803cf3520337deed3d32078238e584"},{"id":"func/_required_scalar_sentinel","name":"_required_scalar_sentinel","line":81,"end_line":91,"hash":"6ccf5a9e4f8a191d825c3149e154f6187b3f0eaf6d83a39cc380e2ccdac4130a"},{"id":"func/_required_field_sentinel","name":"_required_field_sentinel","line":94,"end_line":108,"hash":"f0a918e384c09ece41a6e5d1f7d023541cb7c125d39001e4d620988966f7c932"},{"id":"func/_construct_model_values","name":"_construct_model_values","line":111,"end_line":122,"hash":"4ee65af0c4df79c08e0cd4bbdc9723958612261e008bebd64dcff18dffc73df7"},{"id":"func/construct_model_unvalidated","name":"construct_model_unvalidated","line":125,"end_line":131,"hash":"3a43c16e475796841f19730e2e739a547f973dcdffcaf3731350d797c50f82e6"},{"id":"func/_construct_model","name":"_construct_model","line":134,"end_line":136,"hash":"f5eb79e43d376b2cb3bda00aa654825a2b3c6b5b6624505db2920488d8a3a176"},{"id":"func/_construct_typed_value","name":"_construct_typed_value","line":139,"end_line":145,"hash":"e5af500199e93cd09ec72fe460ae1558f7c6c2b017edf9186465dd9c4417f8b0"},{"id":"func/_construct_unvalidated","name":"_construct_unvalidated","line":148,"end_line":161,"hash":"843d962078660fc08d82a2bacf13af8d6e40f2f17d6f0742ccc5e3831599218b"}]}
# mutate4py-manifest-end
