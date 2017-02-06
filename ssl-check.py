#!/usr/bin/env python

import sys
import time
import logging
import datetime
import argparse
import multiprocessing.pool

import requests
import prettytable


API_ENDPOINT = "https://api.ssllabs.com/api/v2/analyze"
SLEEP = 10
TIMES = 60
DAYS = 10


log = logging.getLogger(__name__)


# Logging have to be configured before load_config,
# where it can (and should) be already used
logfmt = "%(asctime)-15s  %(levelname)-7s %(message)s"
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(logfmt))
handler.setLevel(logging.DEBUG)  # Overridden by configuration
log.addHandler(handler)
log.setLevel(logging.DEBUG)


def format_date(date, only_rel=False):
    now = datetime.datetime.now()
    if date > now:
        td = date - now
    else:
        td = now - date
    seconds = td.total_seconds()
    if seconds >= 60 * 60 * 24:
        unit = 'day'
        value = seconds / 60 / 60 / 24
    elif seconds >= 60 * 60:
        unit = 'hour'
        value = seconds / 60 / 60
    elif seconds >= 60:
        unit = 'minute'
        value = seconds / 60
    else:
        unit = 'second'
        value = seconds
    rel_str = '%d %s' % (value, unit)
    if int(value) != 1:
        rel_str += 's'
    if date > now:
        rel_str = 'in %s' % rel_str
    elif date < now:
        rel_str = '%s ago' % rel_str
    else:
        rel_str = 'right now'
    if only_rel:
        return rel_str
    return '%s (%s)' % (date.strftime('%Y-%m-%d %H:%M'), rel_str)


def request(host, **kwargs):
    """Make a request to SSL Labs, optioanlly triggering new tests"""
    params = {'host': host, 'publish': 'off', 'all': 'done',
              'ignoreMismatch': 'on'}
    params.update(kwargs)
    resp = requests.get(API_ENDPOINT, params=params)
    if not resp.ok:
        try:
            result = resp.json()
            try:
                msg = ' - '.join(map(str, [e['message']
                                           for e in result['errors']]))
            except:
                return result
        except:
            msg = resp.text
        return {'host': host, 'status': 'ERROR', 'statusMessage': msg,
                'retry': True}
    return resp.json()


def get_host_results(host, max_age=0, sleep=SLEEP, times=TIMES):
    kwargs = {'maxAge': max_age} if max_age else {'startNew': 'on'}
    for i in xrange(times):
        result = request(host, **kwargs)
        if result['status'] == 'ERROR':
            if not result.get('retry'):
                log.error('%s: %s', host, result['statusMessage'])
                return result
            log.warning("%s: %s", host, result['statusMessage'])
            time.sleep(sleep)
            continue
        break
    else:
        return result
    kwargs.pop('startNew', None)
    for j in xrange(times - i - 1):
        if result['status'] == 'READY':
            log.info('%s: %s', host, result['status'])
            return result
        elif result['status'] == 'ERROR':
            log.error('%s: %s', host, result['statusMessage'])
            return result
        else:
            log.debug('%s: %s', host, result['status'])
        time.sleep(sleep)
        result = request(host, **kwargs)
    log.error("%s: Timed out" % host)
    return {'host': host, 'status': 'ERROR',
            'statusMessage': "Timed out waiting for results"}


def run(hosts, max_age=0, sleep=SLEEP, times=TIMES,
        warn_days_before=DAYS, grades=None, parallel=0):
    headers = ['host', 'grade', 'ip', 'altNames', 'issuer', 'expires',
               'tested', 'message']
    table = prettytable.PrettyTable(headers)

    def func(host):
        return get_host_results(host, max_age=max_age,
                                sleep=sleep, times=times)

    threads = min(parallel, len(hosts)) if parallel else len(hosts)
    if threads > 1:
        pool = multiprocessing.pool.ThreadPool(processes=threads)
        async_result = pool.map_async(func, hosts)
        while True:
            try:
                results = async_result.get(1)
            except multiprocessing.TimeoutError:
                continue
            except KeyboardInterrupt:
                log.warning("Received SIGTERM, exiting")
                return
            break
    else:
        results = map(func, hosts)
    log.info("Completed polling for results")

    ok = True

    for result in results:
        host = result['host']
        if result.get('testTime'):
            tested = format_date(
                datetime.datetime.fromtimestamp(result['testTime'] / 1000),
                only_rel=True
            )
        else:
            tested = 'N/A'
        if result['status'] == 'ERROR':
            log.error('%s: %s', host, result['statusMessage'])
            table.add_row([host, 'ERROR', '', '', '', '', tested,
                           result['statusMessage']])
            ok = False
            continue
        for endpoint in result['endpoints']:
            ip_addr = endpoint['ipAddress']
            if 'grade' not in endpoint:
                log.error('%s: %s', host, endpoint['statusMessage'])
                table.add_row([host, 'ERROR', ip_addr, '', '', '', tested,
                               endpoint['statusMessage']])
                ok = False
                continue
            grade = endpoint['grade']
            cert = endpoint['details']['cert']
            issuer = cert['issuerLabel']
            alt_names = cert['altNames']
            expires = datetime.datetime.fromtimestamp(cert['notAfter'] / 1000)
            now = datetime.datetime.now()
            days = (expires - now).days
            if expires < now:
                expires_str = 'EXPIRED!'
            elif days < 2:
                expires_str = 'in %s' % (expires - now)
            else:
                expires_str = 'in %d days' % days
            msg = ''
            error = False
            if expires < now:
                msg = 'Certificate expired'
                error = True
            elif days < warn_days_before:
                msg = "Certificate expires in %d days" % days
                error = True
            if grades and grade not in grades:
                if msg:
                    msg += ' - '
                msg += 'Bad grade %s' % grade
                error = True
            ok &= not error
            if error:
                log.error('%s: %s', host, msg)
            else:
                log.info('%s: OK, grade is %s, expires in %d days',
                         host, grade, days)
            table.add_row([host, grade, ip_addr,
                           ', '.join(alt_names)[:64], issuer,
                           format_date(expires), tested, msg or 'OK'])
    print
    print table
    print
    return ok


def main():
    parser = argparse.ArgumentParser(
        description="Check SSL/TLS certificates of hosts using SSL Labs Scan",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('-c', '--cache-max-age', metavar='HOURS',
                        type=int, default=0,
                        help=("Use cached results with given age in hours. "
                              "Zero (default) will always trigger a test."))
    parser.add_argument('-s', '--sleep', metavar='SECS',
                        type=int, default=SLEEP,
                        help=("Sleep for that many seconds, between result "
                              "requests for each host."))
    parser.add_argument('-t', '--times', metavar='NUM',
                        type=int, default=TIMES,
                        help=("Attempt that many times to get results."))
    parser.add_argument('-e', '--warn-expiration', metavar='DAYS',
                        type=int, default=DAYS,
                        help=("Exit with error if certificate will expire in "
                              "the given number of days or less."))
    parser.add_argument('-g', '--grade', nargs='*',
                        help=("Exit with error if grade doesn't match the one "
                              "specified. Can be used multiple times to "
                              "whitelist multiple grades. For example, "
                              "`-g A+ A A-`"))
    parser.add_argument('-p', '--parallel', metavar='THREADS',
                        type=int, default=0,
                        help=("How many host results should be queried in "
                              "parallel. If unset, it will run everything in "
                              "parallel. Reduce to avoid being blocked by "
                              "SSL Labs. Set to 1 to run everything "
                              "serially."))
    parser.add_argument('host', nargs='+',
                        help="Specify a host to connect to.")
    args = parser.parse_args()

    ok = run(args.host, max_age=args.cache_max_age,
             sleep=args.sleep, times=args.times,
             warn_days_before=args.warn_expiration, grades=args.grade,
             parallel=args.parallel)

    if not ok:
        log.error("Exiting with errors")
        sys.exit(1)
    log.info("Completed successfully")


if __name__ == "__main__":
    main()
