#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>

int is_num(char *name)
{
	int i = 0;
	while(name[i] != '\0')
	{
		if(isdigit(name[i]) == 0)
			return 0;
		i++;
	}
	return 1;
}

int main()
{

	struct dirent *entry;
	DIR *dir;
	dir = opendir("/proc");

	if(dir == NULL)
	{
		printf("Couldn't open directory");
		return 1;
	}

	while((entry = readdir(dir)) != NULL)
		{
			if((is_num(entry->d_name)) == 1)
			{
				char path[512];
				snprintf(path, sizeof(path), "/proc/%s/status", entry->d_name);

				FILE *f;
				f = fopen(path, "r");
				if(fopen == NULL)
					continue;

				char line[256];
				while(fgets(line, sizeof(line),f))
				{
					if(strncmp(line, "Name", 4) == 0)
					{
						printf("PID: %s -> %s\n", entry->d_name, line);
						break;
					}
				}
				
			}
		}
	closedir(dir);
	return 0;
}
