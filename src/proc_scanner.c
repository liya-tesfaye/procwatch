#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
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

struct list {
	char pid[256];
    char name[256];
};

struct box {
    struct list *p;
    int cap;
    int count;
};

int main()
{

	struct dirent *entry;
	DIR *dir;

	struct timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 500000000L;

    struct box arr;
	struct box p_arr;
	p_arr.cap = 10;
	p_arr.count = 0;
    p_arr.p = malloc(p_arr.cap * sizeof(struct list));

	int first_scan = 1;

	while(1)
	{
	    arr.cap = 10;
		arr.count = 0;
	    arr.p = malloc(arr.cap * sizeof(struct list));

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
					if(f == NULL)
						continue;

					if(arr.count == arr.cap)
			        {
						arr.cap = 2 * arr.cap;
						struct list *temp = realloc(arr.p, arr.cap * sizeof(struct list));
						if(temp != NULL)
							arr.p = temp;
					}

					char line[256];
					while(fgets(line, sizeof(line),f))
					{
						if(strncmp(line, "Name:", 5) == 0)
						{
							strcpy(arr.p[arr.count].pid, entry->d_name);
							sscanf(line, "Name:%255s", arr.p[arr.count].name);
							//strcpy(arr.p[arr.count].name, line);
							//printf("PID: %s -> %s\n", arr.p[arr.count].pid, arr.p[arr.count].name);
							arr.count++;
							break;
						}
					}
					fclose(f);
				}
			}

			if(first_scan == 0)
			{
				for(int k = 0; k < arr.count; k++)
				{
					int found = 0;
					for(int m = 0; m < p_arr.count; m++)
					{
						if(strcmp(arr.p[k].pid, p_arr.p[m].pid) == 0)
						{
							found = 1;
							break;
						}
					}
					if(found == 0)
						printf("[+] New Process: %s (%s)\n", arr.p[k].pid, arr.p[k].name);
				}

				for(int k = 0; k < p_arr.count; k++)
				{
					int exist = 0;
					for(int m = 0; m < arr.count; m++)
					{
						if(strcmp(p_arr.p[k].pid, arr.p[m].pid) == 0)
						{
							exist = 1;
							break;
						}
					}
					if(exist == 0)
						printf("[-] Process exited: %s (%s)\n", p_arr.p[k].pid, p_arr.p[k].name);
				}
			}
			if(arr.count > p_arr.cap)
			{
				p_arr.cap = arr.cap;
				struct list *temp = realloc(p_arr.p, p_arr.cap * sizeof(struct list));
				if(temp != NULL)
					p_arr.p = temp;
			}

			for(int i = 0; i < arr.count; i++)
			{
				strcpy(p_arr.p[i].pid,arr.p[i].pid);
				strcpy(p_arr.p[i].name, arr.p[i].name);
			}
			p_arr.count = arr.count;
			first_scan = 0;
		free(arr.p);
		closedir(dir);
		nanosleep(&ts, NULL);
	}

	return 0;
}
