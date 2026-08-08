"""Parameterized Jinja2 template loader for the STPA pipeline — clean copy.

Unlike the existing ``scenario_forge.prompts`` module which hardcodes the
prompts directory, this loader accepts a ``Path`` so each STPA sub-project
can pass its own ``prompts/`` directory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import jinja2


class TemplateLoader:
    """Jinja2 template loader bound to a specific prompts directory.

    Args:
        prompts_dir: Directory containing ``.j2`` template files.
    """

    def __init__(self, prompts_dir: Path) -> None:
        self.prompts_dir = Path(prompts_dir).resolve()
        self._env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.prompts_dir)),
            keep_trailing_newline=True,
            undefined=jinja2.StrictUndefined,
        )

    def render_prompt(self, template_name: str, **kwargs: object) -> str:
        """Render a Jinja2 template with the given variables.

        Args:
            template_name: Filename of the template (e.g. ``"call0_system.j2"``).
            **kwargs: Template variables.

        Returns:
            The rendered prompt string.
        """
        template = self._env.get_template(template_name)
        return template.render(**kwargs)

    def hash_prompt_templates(self) -> dict[str, str]:
        """Return SHA-256 hashes for every ``.j2`` file in the prompts directory.

        Returns:
            Dict mapping template filename to its 64-character hex digest.
        """
        hashes: dict[str, str] = {}
        for path in sorted(self.prompts_dir.glob("*.j2")):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            hashes[path.name] = digest
        return hashes


def hash_prompt_templates(prompts_dir: Path) -> dict[str, str]:
    """Return SHA-256 hashes for every ``.j2`` file in *prompts_dir*.

    Args:
        prompts_dir: Directory containing ``.j2`` template files.

    Returns:
        Dict mapping template filename to its 64-character hex digest.
    """
    return TemplateLoader(prompts_dir).hash_prompt_templates()


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T11:55:37Z","module_hash":"bb453980269f39497e9f3fded162f09e98e8499e351e09080d7f322a665676e6","functions":[{"id":"func/TemplateLoader.__init__","name":"__init__","line":23,"end_line":29,"hash":"40c5c66ab688c6af0921b638e02938c21f736978e0c76a25b8b566681c36207c"},{"id":"func/TemplateLoader.render_prompt","name":"render_prompt","line":31,"end_line":42,"hash":"4e185463d9e3d75d2129f4eaea737763577787d609c294a58d0566bc9f3828d8"},{"id":"func/TemplateLoader.hash_prompt_templates","name":"hash_prompt_templates","line":44,"end_line":54,"hash":"8c5db8250e309e67613891803a7ff6d3bd6fd1074781452ee2936bc4e4400e7b"},{"id":"func/hash_prompt_templates","name":"hash_prompt_templates","line":57,"end_line":66,"hash":"e51f5ecc835a6ca5115ba6df6114bdbed6aba65678df919df4d6860792c91488"}]}
# mutate4py-manifest-end
