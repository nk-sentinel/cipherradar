from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class CamelCaseModel(BaseModel):
    """Base schema that converts snake_case fields to camelCase in JSON output."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,  # accept both snake_case and camelCase as input
    )
