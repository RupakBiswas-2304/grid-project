import sys


def progress(count: int, total: int, status=''):
    bar_length = 60

    filled_len = int(round(bar_length * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = '\033[0;32m—\033[0;0m' * filled_len + \
        '\033[0;31m—\033[0;0m' * (bar_length - filled_len)

    sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', status))
    sys.stdout.flush()


def reset():
    sys.stdout.write(' ' * 100 + '\r')
    sys.stdout.flush()
