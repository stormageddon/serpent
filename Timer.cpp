#include <stdio.h>
#include <time.h>

class Timer
{
	private:
		clock_t start;
		clock_t end;

	public:
		void StartTimer()
		{
			start = clock();
		}

		double EndTimer()
		{
			double diffticks;
			double diffms;
	
			end = clock();
			diffticks = end - start;
			diffms = (diffticks)/(CLOCKS_PER_SEC/1000);

			return diffms;
		}
};
