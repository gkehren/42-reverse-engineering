#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

class N
{
	private:
		char *annotation;
		int value;

	public:
		N(int v)
		{
			value = v;
		}

		void setAnnotation(char *a)
		{
			memcpy(annotation, a, strlen(a));
		}

		int operator-(N &v)
		{
			return value -= v.value;
		}

		int operator+(N &v)
		{
			return value += v.value;
		}
};

int main(int argc, const char **argv, const char **envp)
{
	if ( argc <= 1 )
		_exit(1);
	N *v4 = new N(5);
	N *v6 = new N(6);
	v4->setAnnotation((char *)argv[1]);
	v6->doSomething();
	return 0;
}
