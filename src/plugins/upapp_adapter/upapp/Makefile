

all:
	gcc -shared  -o libupapp.so upapp_main.c sys_timer.c -fPIC -pthread -lrt -O2 
clean:
	rm -rf libupapp.so *.o
