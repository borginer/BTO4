Ariel Itskovich 214501348
Yovel Hazan 206475204

compilation (from src dir)
mkdir obj-intel64
make obj-intel64/ex4.so

running given so:
$PIN_ROOT/pin -t ./ex4.so -- ../bzip2 -k -f ../input-long.txt
running from src:
$PIN_ROOT/pin -t obj-intel64/ex4.so -- ../bzip2 -k -f ../input-long.txt
