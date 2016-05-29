__author__ = 'rragan'

import multiprocessing.dummy as mp

def cube(x):
    return x**3
if __name__ == '__main__':
    pool = mp.Pool(processes=4)
    results = [pool.apply(cube, args=(x,)) for x in range(1,7)]
    print(results)

    pool = mp.Pool(processes=4)
    results = pool.map(cube, range(1,7))
    print(results)

    pool = mp.Pool(processes=4)
    results = [pool.apply_async(cube, args=(x,)) for x in range(1,7)]
    output = [p.get() for p in results]
    print(output)

