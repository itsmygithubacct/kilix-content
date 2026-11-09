"""Exact owned derivative selected for Ask; other model URLs stay upstream."""

VERSIONS = {'lfm3-kilix-commands': 'lfm3-kilix-commands-20261103-v1',
            'lfm2-kilix-commands': 'lfm2-kilix-commands-20261106-v9',
            'needle3-kilix-commands': 'needle3-kilix-commands-20261026-v9'}


def selected_commands_archive(record, url):
    # This raw-JSON check stays independent of the production parser. It grants
    # no exception to another record, publisher, version, or nested URL.
    version = VERSIONS.get(record.get('id'))
    expected = ('https://github.com/itsmygithubacct/kilix-needle/releases/download/'
                + version + '/' + version + '.tar.gz') if version else None
    return (version is not None
            and record.get('provider') == 'kilix-needle'
            and record.get('version') == version and url == expected)


FEMALE02_FILES = (
    'https://github.com/itsmygithubacct/kilix-voice/releases/download/kilix-female-02-epoch80/kilix-female-02.onnx',
    'https://github.com/itsmygithubacct/kilix-voice/releases/download/kilix-female-02-epoch80/kilix-female-02.onnx.json',
)


def selected_female02_file(record, url):
    """The two epoch-80 files, and no other Kilix-hosted speech file."""
    return (record.get('id') == 'kilix-female-02'
            and record.get('provider') == 'kilix-piper-tts'
            and record.get('version') == 'kilix-female-02-epoch80'
            and url in FEMALE02_FILES)


NOLOOP02_FILES = (
    'https://github.com/itsmygithubacct/kilix-llm/releases/download/qwen-0.8b-no-loop-02/qwen-0.8b-no-loop-02.gguf',
)


def selected_noloop02_file(record, url):
    """The one no-loop-02 GGUF, and no other Kilix-hosted language model file."""
    return (record.get('id') == 'qwen-0.8b-no-loop-02'
            and record.get('provider') == 'kilix-llm'
            and record.get('version') == 'qwen-0.8b-no-loop-02'
            and url in NOLOOP02_FILES)


def selected_owned_file(record, url):
    return selected_female02_file(record, url) or selected_noloop02_file(record, url)


def selected_owned_bytes(record, url):
    return selected_commands_archive(record, url) or selected_owned_file(record, url)
