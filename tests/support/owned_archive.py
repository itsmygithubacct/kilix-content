"""Exact owned derivative selected for Ask; other model URLs stay upstream."""

VERSION = 'lfm2-kilix-commands-20261023-v5'
URL = ('https://github.com/itsmygithubacct/kilix-needle/releases/download/'
       + VERSION + '/' + VERSION + '.tar.gz')


def selected_commands_archive(record, url):
    # This raw-JSON check stays independent of the production parser. It grants
    # no exception to another record, publisher, version, or nested URL.
    return (record.get('id') == 'lfm2-kilix-commands'
            and record.get('provider') == 'kilix-needle'
            and record.get('version') == VERSION and url == URL)
