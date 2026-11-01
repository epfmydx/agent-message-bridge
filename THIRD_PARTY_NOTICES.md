# Third-party dependencies

The project source is licensed under [MIT](LICENSE), copyright 2026 EPFMy DigitalX Services. Dependency packages retain their own licenses. This source distribution contains dependency requirements, rather than vendored Python packages, native libraries, fonts or UI frameworks. Preserve required upstream notices when redistributing those materials.

| Dependency group | License metadata for the pinned source dependencies |
| --- | --- |
| Authlib, click, Flask, idna, itsdangerous, Jinja2, joserfc, MarkupSafe, pycparser, Werkzeug | BSD-3-Clause |
| blinker, charset-normalizer, gunicorn, jmespath, six, SQLAlchemy, urllib3 | MIT |
| cffi | MIT-0 |
| boto3, botocore, s3transfer | Apache-2.0; retain applicable NOTICE files |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| packaging | Apache-2.0 OR BSD-2-Clause |
| python-dateutil | Apache/BSD terms; preserve the complete upstream license |
| typing_extensions | PSF-2.0 |
| certifi | MPL-2.0 |
| psycopg, psycopg-binary | LGPL-3.0-only |
| pytest, PyYAML (development) | MIT |

The manifest is an inventory, not a replacement for each package's actual license files. See [the dependency lock](requirements.lock), [MPL distribution guidance](https://www.mozilla.org/en-US/MPL/2.0/FAQ/), [Psycopg licensing](https://github.com/psycopg/psycopg/blob/master/LICENSE.txt), and [Apache redistribution terms](https://www.apache.org/licenses/LICENSE-2.0).

A built Python/Linux container or bundled wheel distribution includes additional software beyond this source tree. Before redistributing one, inspect its exact platform/base digest, Python/OS/native-library contents, license texts, notices and source-access/replacement requirements. The project does not publish container images. [Psycopg binary packaging](https://www.psycopg.org/psycopg3/docs/basic/install.html) and [official Python image licensing](https://github.com/docker-library/docs/blob/master/python/README.md#license) describe relevant boundaries.
