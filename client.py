from rdt import RDTSocket
import time
from difflib import Differ

if __name__=='__main__':
    client = RDTSocket(debug=False)

    # client = socket(AF_INET, SOCK_STREAM) # check what python socket does
    client.connect(('127.0.0.1', 9999))

    echo = b''
    count = 2
    slice_size = 2048
    blocking_send = False

    with open('alice.txt', 'r') as f:
        data = f.read()
        encoded = data.encode()
        assert len(data) == len(encoded)

    '''
    check if your rdt pass either of the two
    mode A may be significantly slower when slice size is small
    '''
    if blocking_send:
        print('transmit in mode A, send & recv in slices')
        slices = [encoded[i*slice_size:i*slice_size+slice_size] for i in range(len(encoded)//slice_size+1)]
        assert sum([len(slice) for slice in slices]) == len(encoded)

        start = time.perf_counter()
        for i in range(count): # send 'alice.txt' for count times
            for slice in slices:
                client.send(slice)
                print('send2')
                reply = client.recv(slice_size)
                echo += reply

    else:
        print('transmit in mode B')
        start = time.perf_counter()
        for i in range(count):
            client.send(encoded)
            while len(echo) < len(encoded)*(i+1):
                reply = client.recv(slice_size)
                echo += reply

    client.close()

    print(f'transmitted {len(encoded) * count} bytes in {time.perf_counter() - start}s')

    '''
    make sure the following is reachable
    '''
    with open('output1.txt', 'w') as f:
        f.write(data*count)

    with open('output2.txt', 'w') as f:
        f.write(echo.decode())


    # diff = Differ().compare((data*count).splitlines(keepends=True), echo.decode().splitlines(keepends=True))
    # for line in diff:
    #     if not line.startswith('  '): # check if data is correctly echoed
    #         print(line)
