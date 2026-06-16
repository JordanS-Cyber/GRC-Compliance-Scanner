def parse_colon_table(text: str) -> dict:
    """Parse 'Label:    Value' style output (e.g. `net accounts`) into a dict.

    `net accounts` has no JSON/structured output mode, so this is the only
    portable way to read it. partition() (not split) is used because labels
    themselves can be long and the value is always everything after the
    first colon.
    """
    result = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        label = label.strip()
        value = value.strip()
        if label and value:
            result[label] = value
    return result
