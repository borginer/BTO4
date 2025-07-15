

compilation (from src dir)
mkdir obj-intel64
make obj-intel64/ex3.so

running given so:
$PIN_ROOT/pin -t ./ex3.so -- ../bzip2 -k -f ../input-long.txt
running from src:
$PIN_ROOT/pin -t obj-intel64/ex3.so -- ../bzip2 -k -f ../input-long.txt
