#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int64_t entries;
int ent;

int load_config(){
    FILE *fp = fopen("scion_filter.cfg", "r");
    if(fp == NULL) {
        perror("Unable to open file!");
        exit(1);
    }
 
    char line[256];
    char arg[256];
    while(fgets(line, sizeof(line), fp) != NULL) {
        if(line[0] == '#'){
            continue;
        }
        if(strcmp(line, "stats_interval:\n") == 0){
            fgets(arg, sizeof(arg), fp);
            entries = atoi(arg);
        }else if(strcmp(line, "drkey_grace_period:\n") == 0){
            fgets(arg, sizeof(arg), fp);
            ent = atoi(arg);
        }
        printf("%s",line);
    }
    printf("DONE\n");
    printf("%d\n", entries);
    printf("%d\n", ent);

    fclose(fp);
    return 0;
}

void print_cli_usage(){
    printf("\nCurrently supported CLI commands:\n\n"
           "  reload  Reloads the rate-limit config file\n"
	       "    stop  terminates the application\n"
	       "    help  Prints this info\n\n"
		  );
}

int cli_read_line(void){
    char *line = NULL;
    ssize_t bufsize = 0; // have getline allocate a buffer for us
    getline(&line, &bufsize, stdin);
    if(strcmp(line, "reload\n") == 0){
        load_config();
    }else if (strcmp(line, "stop\n") == 0){
        return 0;
    }else{
        print_cli_usage();
    }
    return 1;
}


void prompt(void){
    int status;

    do {
        printf("> ");
        status = cli_read_line();
  } while (status);
}



int main(void) {

    load_config(); 
    printf("\n");
    prompt();   
}