#coding: utf-8

import os
import sys
from os import path
from time import time as timestamp
from time import sleep
import logging

try:
    system, machine = os.uname()[0], os.uname()[4]
    if system not in ('Linux', ) or machine not in ('i686', 'x86_64'):
        raise AssertionError('Unsupported platform.')
    import sandbox
    if not hasattr(sandbox, '__version__') or sandbox.__version__ < '0.3.4-3':
        raise AssertionError('Unsupported sandbox vesion.')
except AssertionError as e:
    sys.stderr.write(str(e))
    sys.exit(os.EX_UNAVAILABLE)

import oursql
import sh

from sandbox import Sandbox, SandboxPolicy
from sandbox import (S_EVENT_SYSRET, S_EVENT_SYSCALL, S_ACTION_KILL,
                     S_ACTION_CONT, S_RESULT_RF)

import secret


class DB(object):
    host = secret.host
    host = secret.host
    user = secret.user
    password = secret.password
    db = secret.db

    def __init__(self):
        self.conn = oursql.connect(self.host, self.user, self.password,
                                   db=self.db)

    def __del__(self):
        self.conn.close()

    @property
    def cursor(self):
        return self.conn.cursor(oursql.DictCursor)


class SolutionsSandbox(Sandbox, SandboxPolicy):
    sc_table = None
    # white list of essential linux syscalls for statically-linked C programs
    sc_safe = dict(i686=set([0, 3, 4, 19, 45, 54, 90, 91, 122, 125, 140,
                             163, 192, 197, 224, 243, 252, ]),
                   x86_64=set([0, 1, 5, 8, 9, 10, 11, 12, 16, 25, 63, 158, 219,
                               231, ]), )

    def __init__(self, *args, **kwargs):
        # initialize table of system call rules
        self.sc_table = [self._KILL_RF, ] * 1024
        for scno in SolutionsSandbox.sc_safe[machine]:
            self.sc_table[scno] = self._CONT
        # initialize as a polymorphic sandbox-and-policy object
        SandboxPolicy.__init__(self)
        Sandbox.__init__(self, *args, **kwargs)
        self.policy = self

    def result_name(self, r):
        return ('PD', 'OK', 'RF', 'ML', 'OL', 'TL', 'RT', 'AT', 'IE', 'BP')[r]\
            if r in range(10) else None

    def probe(self):
        # add custom entries into the probe dict
        d = Sandbox.probe(self, False)
        d['cpu'] = d['cpu_info'][0]
        d['mem'] = d['mem_info'][1]
        d['result_name'] = self.result_name(self.result)
        d['result'] = self.result
        return d

    def __call__(self, e, a):
        # handle SYSCALL/SYSRET events with local rules
        if e.type in (S_EVENT_SYSCALL, S_EVENT_SYSRET):
            if machine == 'x86_64' and e.ext0 != 0:
                return self._KILL_RF(e, a)
            return self.sc_table[e.data](e, a)
        # bypass other events to base class
        return SandboxPolicy.__call__(self, e, a)

    def _CONT(self, e, a):  # continue
        a.type = S_ACTION_CONT
        return a

    def _KILL_RF(self, e, a):  # restricted func.
        a.type, a.data = S_ACTION_KILL, S_RESULT_RF
        return a


class Solutions(DB):
    sandbox_path = path.abspath('./tmp')
    err_log = 'err'

    result_code = {
        1: 'AC',
        3: 'MLE',
        4: 'OLE',
        5: 'TLE',
        8: 'IE',
        11: 'CE'
    }

    default_limit = {
        'time': 1000,
        'memory': 128 * 1024 * 1024,
    }

    def __init__(self, logger=None):
        super(Solutions, self).__init__()
        self.logger = logger or logging.getLogger(__name__)

    def sandbox(self, child):
        return path.join(self.sandbox_path, child)

    def src(self, src_id):
        cur = self.cursor
        cur.execute('''select content from content where id = ?''', (src_id, ))
        rec = cur.fetchone()
        cur.close()
        if rec:
            return rec['content'] or ''

    @property
    def pending(self):
        cur = self.cursor
        cur.execute('''select id, source_id from solution where status = 0''')
        rec = cur.fetchone()
        cur.close()
        if rec:
            rec['source'] = self.src(rec['source_id'])
        return rec

    def report(self, id, short_result, detail_result, err_result):
        cur = self.cursor
        cur.execute('''update solution
        set short_result = ?, detail_result = ?, err_result = ?, status = 1
        where id = ?''', (short_result, detail_result, err_result, id))
        cur.close()
        return True

    def result(self, probe_result):
        code = probe_result.get('result', 8)
        return self.result_code.get(code, self.result_code[8])

    def compile(self, id, name, source):
        src = '%s.c' % (name)
        with open(src, 'w') as f:
            f.write(source)

        try:
            work = sh.gcc(src, '-O2', '--static', '-Wall', '-lm', '-std=c99',
                          o=name, _ok_code=[0])
            work.wait()
            sh.rm(src).wait()
            return (0, '', '')
        except sh.ErrorReturnCode_1 as e:
            return (self.result_code[11], '', e.stderr.decode('utf-8'))

    def run(self, id, name, time, memory, fin=None, fout=None):
        null, zero = open('/dev/null', 'w'), open('/dev/zero', 'r')
        err = open(self.sandbox(self.err_log), 'w')
        fin = self.sandbox(fin) if fin else fin
        fout = self.sandbox(fout) if fout else fout
        sandbox = SolutionsSandbox(**{
            'args': name,
            'stdin': open(fin, 'r') if fin else zero,
            'stdout': open(fout, 'w') if fout else null,
            'stderr': err,
            'quota': {
                'wallclock': 30000,
                'cpu': time,
                'memory': memory,
                'dick': 1024 * 1024 * 10,  # 10 MB
            }
        })
        sandbox.run()
        probe_result = sandbox.probe()
        null.close()
        zero.close()
        err.close()

        sh.rm(name).wait()
        short_result = self.result(probe_result)
        with open(self.sandbox(self.err_log), 'r') as f:
            err_result = f.read()
        sh.rm(self.sandbox(self.err_log)).wait()
        if fout:
            with open(fout, 'r') as f:
                detail_result = f.read()
            sh.rm(fout).wait()
        else:
            detail_result = err_result

        return (short_result, detail_result, err_result)

    def judge(self, id, source, time=None, memory=None, fin=None, fout=None):
        name = self.sandbox('%s%d' % (str(id), int(timestamp())))
        time = time or self.default_limit.get('time')
        memory = memory or self.default_limit.get('memory')

        ret = self.compile(id, name, source)
        self.logger.debug('\tCompile result %s %s' % (str(ret[0]), ret[2]))
        if ret[0] == 0:
            ret = self.run(id, name, time, memory, fin, fout)
            self.logger.debug('\tRun result %s %s %s' %
                              (str(ret[0]), ret[1], ret[2]))
        self.report(id, ret[0], ret[1], ret[2])

    def poll(self, sleep_time=1):
        self.logger.info('Start polling...')
        while True:
            pending = self.pending
            if pending:
                self.logger.info('Found new job %s', str(pending['id']))
                pending.pop('source_id')
                self.judge(**pending)
            sleep(sleep_time)


def main():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    file_handler = logging.FileHandler('judge.log')
    file_handler.setLevel(logging.DEBUG)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    polling = Solutions(logger)
    polling.poll()


if __name__ == '__main__':
    main()
