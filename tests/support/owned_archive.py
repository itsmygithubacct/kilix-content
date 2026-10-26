"""Exact owned derivative selected for Ask; other model URLs stay upstream."""

VERSIONS = {'lfm2-kilix-commands': 'lfm2-kilix-commands-20261023-v5',
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
