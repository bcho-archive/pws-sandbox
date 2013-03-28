#coding: utf-8

from os import path

from judge import Solutions


class TestSolutions(Solutions):
    testcases = [
        dict(n='normal.c', t=5, i='normal.in', e='AC'),
        dict(n='normal.c', i='normal.in', o='normal.out', e='AC'),
        dict(n='normal.c', t=1, e='TLE'),
        dict(n='mle.c', t=1000 * 1000, m=128, e='MLE'),
        dict(n='ce.c', e='CE'),
        dict(n='re.c', e='IE'),
        dict(n='exit.c', e='AC'),
        dict(n='fork.c', e='IE')
    ]
    basepath = path.abspath('./tests')

    def report(self, id, short_result, detail_result, err_result):
        print (id, short_result, detail_result, err_result)

    def test(self):
        _ = lambda x: path.join(self.basepath, x) if x else None
        for i in self.testcases:
            print 'Running %s, excepted %s' % (i['n'], i['e'])
            rec = {
                'id': i['e'],
                'time': i.get('t', 1000),
                'source': open(_(i['n'])).read(),
                'memory': i.get('m', 128 * 1024 * 1024),
                'fin': _(i.get('i')), 'fout': _(i.get('o'))
            }
            self.judge(**rec)


if __name__ == '__main__':
    test = TestSolutions()
    test.test()
