#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include<string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>
#define MAX_PATH_LEN 256
#define GREAT_MAX 1200005

typedef struct SH{
	char sect_name[13];
	uint32_t sect_type;
	uint32_t sect_offset;
	uint32_t sect_size;
}sect_head;

typedef struct head {
	uint32_t version;
	uint8_t nbOfSections;
	sect_head sh;
	uint16_t header_size;
	char magic[2];
}mySF;

mySF SF;
char sf_details[17][27];
uint32_t offsets[27];
uint32_t s_types[17];

int isFile(const char* path){

	int fd = -1;
	char file[MAX_PATH_LEN * 5];
	struct stat stBuf;

	if(stat(path, &stBuf) == 0){
		strcpy(file ,strrchr(path, '/'));
		strcpy(file, file + 1);
		if(!S_ISREG(stBuf.st_mode)){
			//printf("ERROR\ninvalid file\n");
			return 0;	
		}
	}

	fd = open(path, O_RDONLY );
	if(fd == -1){
		perror("Could not open file");
		return 0;
	}

	return fd;
}

void showFileDetails(uint8_t sectNo){
	int i;
	printf("SUCCESS\n");
	printf("version=%d\n", SF.version);
	printf("nr_sections=%d\n",SF.nbOfSections);
	for(i = 1; i <= sectNo ; i++){
		printf("section%d:%s\n",i,sf_details[i]);
	}
	memset(sf_details,0 ,sizeof(memset));
} 


void showCorruption(const char* err){
	char error[50];
	strcpy(error, "ERROR\n");
	strcat(error,"\0");
	strcat(error,err);
	strcat(error, "\0");
	printf("%s\n",error);
	memset(sf_details,0 ,sizeof(memset));
}


uint8_t parseFile(int fd, int mod){
	int i;
	
	lseek(fd, -4, SEEK_END);
	read(fd, &SF.header_size, 2);
	
	lseek(fd, -SF.header_size, SEEK_END);

	read(fd, &SF.version, sizeof(SF.version));
	if(SF.version < 39 ||  SF.version > 147){
		showCorruption("wrong version");
		return 0;
	}
	
	read(fd, &SF.nbOfSections, 1);
	
	if(SF.nbOfSections < 4 || SF.nbOfSections > 15){
		showCorruption("wrong sect_nr");
		return 0;
	
	}
	
	for(i = 1; i <= SF.nbOfSections; i++){	
		
		if(read(fd, &SF.sh.sect_name, sizeof(SF.sh.sect_name)) == -1){
			return 0;
		}
		
		if(read(fd, &SF.sh.sect_type, sizeof(SF.sh.sect_type)) != -1) {
			if(SF.sh.sect_type != 89 && SF.sh.sect_type != 86 && SF.sh.sect_type != 73){
				showCorruption("wrong sect_types	");
				return 0;
			}
		}
		if(mod == 2){
			s_types[i] = SF.sh.sect_type;
		}

		if(read(fd, &SF.sh.sect_offset, sizeof(SF.sh.sect_offset)) == -1){
			return 0;
		}

		if(mod == 1){
			offsets[i] = SF.sh.sect_offset;
		}

		 if(read(fd, &SF.sh.sect_size, sizeof(SF.sh.sect_size)) == -1){
			return 0;
		}

		snprintf(sf_details[i], sizeof(sf_details[i]), " %s %d %d",SF.sh.sect_name,SF.sh.sect_type,SF.sh.sect_size);
		strcat(sf_details[i],"\0");
		memset(&SF.sh, 0, sizeof(SF.sh));
	}


	lseek(fd, 2, SEEK_CUR);

	if(read(fd, &SF.magic, sizeof(SF.magic)) != -1){
		if(strcmp(SF.magic,"rc") != 0){
			showCorruption("wrong magic");
			return 0;
		}
	}	

	return SF.nbOfSections;
}

void displayLine(const char *dl){
	int i;
	printf("SUCCESS");
	for(i = strlen(dl) - 1; i >= 0 ; i--){
		printf("%c", dl[i]);
	}
	printf("\n" );
}


void extractLine(int fd,int secNo, int section, int line){
	
	int i = 0;
	int l = 0;
	char buf[GREAT_MAX + 5]; 
	char res[GREAT_MAX + 5];
	strcat(buf,"");
	memset(buf, 0, sizeof(buf));
	memset(res, 0, sizeof(res));

	lseek(fd, 0, SEEK_SET);
	lseek(fd, offsets[section], SEEK_CUR);
	
	while(read(fd ,&buf[i], 1)){

		if(l == line){
			break;
		}

		i++;
			if(buf[i - 1] == '\n'){
				l++;
				i = 0;
				strcpy(res, buf);
				memset(buf, 0, sizeof(buf));
			}
		
		
	}	
	
	displayLine(res);
	return;
	
}

int correctSectionType(int fd, const char *path){
	
	int i,nb_sec,cnt = 0;
	
	nb_sec = parseFile(fd, 2);
	for( i = 1; i < nb_sec; i++){
		 if( s_types[i] == 89){
		 	cnt++;
		}
	}
	memset(s_types, 0, sizeof(s_types));
	memset(sf_details, 0, sizeof(sf_details));
	if(cnt >= 3){
		return 1;
	}
	return 0;

}

void findAll(const char *pth){

	char full_pth[MAX_PATH_LEN  + 5];
	memset(full_pth, 0, sizeof(full_pth));
	DIR *dir = NULL;
	struct dirent *dirEntry = NULL;
	struct stat stBuf;
	int fd;

	dir = opendir(pth);

	if(dir == NULL){
		printf("ERROR\ninvalid directory path\n");
		return;
	}

	
	while((dirEntry = readdir(dir)) != NULL){
		if(strcmp(dirEntry->d_name , ".") != 0 && strcmp(dirEntry->d_name , "..") != 0){	
			snprintf(full_pth, MAX_PATH_LEN + 1, "%s/%s", pth, dirEntry->d_name);
			if(stat(full_pth, &stBuf) == 0){
				if((fd = isFile(full_pth)) != 0 ){
					if(correctSectionType(fd, full_pth)){
						strcat(full_pth,"\0");
						printf("%s\n",full_pth );
					}
				}else{
					if(S_ISDIR(stBuf.st_mode)){
						findAll(full_pth);
					}
				}
			}
		}
	}
	closedir(dir);
}

void listDirContents(const char *path){

		DIR* dir = NULL;
		struct dirent *dirEntry = NULL;
		char finPath[MAX_PATH_LEN];

		dir = opendir(path);
		
		if(dir == NULL){
			printf("ERROR\n invalid directory path \n");
			return;
		}

		strcpy(finPath, path);
		
		while((dirEntry = readdir(dir)) != NULL){
			
			if(strcmp(dirEntry->d_name , ".") != 0 && strcmp(dirEntry->d_name , "..") != 0){
				
				strcat(finPath,"/");
				strcat(finPath, dirEntry->d_name);
				strcat(finPath, "\0");
				printf("%s\n",finPath);
				strcpy(finPath, path);
			}
	}	
	closedir(dir);
}

void listDirContentsRecursively(const char *pth){
	
	char full_pth[MAX_PATH_LEN  + 5];
	memset(full_pth, 0, sizeof(full_pth));
	DIR *dir = NULL;
	struct dirent *dirEntry = NULL;
	struct stat stBuf;

	
	dir = opendir(pth);

	if(dir == NULL){
		printf("Error\n");
		return;
	}

	while((dirEntry = readdir(dir)) != NULL){
		if(strcmp(dirEntry->d_name , ".") != 0 && strcmp(dirEntry->d_name , "..") != 0){	
			snprintf(full_pth, MAX_PATH_LEN + 1, "%s/%s", pth, dirEntry->d_name);
			if(stat(full_pth, &stBuf) == 0){
				strcat(full_pth,"\0");
				printf("%s\n",full_pth );
				if(S_ISDIR(stBuf.st_mode)){
					listDirContentsRecursively(full_pth);
				}
			}
		}
	}
	closedir(dir);
}

bool samePermissions(char *permissions, struct stat st){

	char file_perm[10];
	int i;
	file_perm[0] = (st.st_mode & S_IRUSR) ? 'r' : '-';
    file_perm[1] = (st.st_mode & S_IWUSR) ? 'w' : '-';
    file_perm[2] = (st.st_mode & S_IXUSR) ? 'x' : '-';
    file_perm[3] = (st.st_mode & S_IRGRP) ? 'r' : '-';
    file_perm[4] = (st.st_mode & S_IWGRP) ? 'w' : '-';
    file_perm[5] = (st.st_mode & S_IXGRP) ? 'x' : '-';
    file_perm[6] = (st.st_mode & S_IROTH) ? 'r' : '-';
    file_perm[7] = (st.st_mode & S_IWOTH) ? 'w' : '-';
    file_perm[8] = (st.st_mode & S_IXOTH) ? 'x' : '-';
    file_perm[9] = '\0';
 
    for(i = 0; i < strlen(file_perm) ; i++){
    	if(file_perm[i] != permissions[i]){
    		return 0;
    	}
    }
    return 1;
}

void listAllowedFiles(const char *path, char *permissions){

		char full_pth[MAX_PATH_LEN + 1];
		DIR* dir = NULL;
		struct dirent *dirEntry = NULL;	
		struct stat st;

		dir = opendir(path);

		if(dir == NULL){
			perror("Could not open directory");
			return;
		}

	
		while((dirEntry = readdir(dir)) != NULL){
			
			if(strcmp(dirEntry->d_name , ".") != 0 && strcmp(dirEntry->d_name , "..") != 0){
				snprintf(full_pth,MAX_PATH_LEN + 1, "%s/%s",path, dirEntry->d_name);
				if(stat(full_pth, &st) == 0){
					if(samePermissions(permissions,st)){
						strcat(full_pth, "\0");
						printf("%s\n",full_pth );

					}

				}

			}

		}
	
	closedir(dir);
}


void listSizeSmallerFolders(const char *path,int f_size){
		
		char full_pth[MAX_PATH_LEN + 5];
		struct stat st;
		DIR* dir = NULL;
		struct dirent *dirEntry = NULL;
		
		dir = opendir(path);
		if(dir == NULL){
		
			printf("Could not open directory");
			return;
		}
	
		while((dirEntry = readdir(dir)) != NULL){
				
			if(strcmp(dirEntry->d_name , ".") != 0 && strcmp(dirEntry->d_name , "..") != 0){
				
				snprintf(full_pth, MAX_PATH_LEN + 1, "%s/%s",path, dirEntry->d_name);
				
				 if(stat(full_pth, &st) == 0){
				 	
				 	if(S_ISREG(st.st_mode)){
				 		
						if(st.st_size < f_size){
							strcat(full_pth, "\0");
							printf("%s\n",full_pth );	
						}
					}
				}
			}
			
		}

	closedir(dir);	

}

void listAllowedFilesRecursively(const char* pth, char *permissions){
	char full_pth[MAX_PATH_LEN * 2];
	DIR *dir = NULL;
	struct dirent *dirEntry = NULL;
	struct stat stBuf;
	dir = opendir(pth);

	if(dir == NULL){
		//ERR_MSG("Could not open directory");
		perror("Could not open directory");
			return;
	}

	while((dirEntry = readdir(dir)) != NULL){
		if(strcmp(dirEntry->d_name , ".") != 0 && strcmp(dirEntry->d_name , "..") != 0){
			
			snprintf(full_pth, MAX_PATH_LEN * 2, "%s/%s", pth, dirEntry->d_name);
			
			if(lstat(full_pth, &stBuf) == 0){
				if(samePermissions(permissions,stBuf)){
					strcat(full_pth,"\0");
					printf("%s\n",full_pth );
					if(S_ISREG(stBuf.st_mode) || S_ISDIR(stBuf.st_mode)){
						listAllowedFilesRecursively(full_pth,permissions);
					}
				}
			}
		}
			
	}
	closedir(dir);	
}


void listSizeSmallerFoldersRecursively(const char* pth, int f_size){
	char full_pth[MAX_PATH_LEN * 2];
	DIR *dir = NULL;
	struct dirent *dirEntry = NULL;
	struct stat stBuf;
	dir = opendir(pth);
	
	if(dir == NULL){
			return;
	}

	while((dirEntry = readdir(dir)) != NULL){
		if(strcmp(dirEntry->d_name , ".") != 0 && strcmp(dirEntry->d_name , "..") != 0){
			
			snprintf(full_pth, MAX_PATH_LEN * 2, "%s/%s", pth, dirEntry->d_name);
			
			if(lstat(full_pth, &stBuf) == 0){
				if(S_ISREG(stBuf.st_mode) || S_ISDIR(stBuf.st_mode)){
					if(stBuf.st_size < f_size && S_ISREG(stBuf.st_mode)){
						strcat(full_pth,"\0");
						printf("%s\n",full_pth );
					}
					 listSizeSmallerFoldersRecursively(full_pth,f_size);
				}
			}
		}
			
	}
	closedir(dir);	
}



int main (int argc, char **argv){
    int f_size;
    int section;
    int line;
    int fd1;
    char dir[MAX_PATH_LEN ];
    memset(dir, 0, sizeof(dir));
    uint8_t sectNo;

    char permissions[50];
    memset(permissions, 0, sizeof(permissions));

 	char o1[50];
    memset(o1, 0, sizeof(o1));

    char o2[50];
    memset(o2, 0, sizeof(o2));

	if(argc >= 2){

		if(strcmp(argv[1], "variant") == 0){       
		    printf("48059\n");
		}


		if(argv[1] != NULL){
  			//LIST
			if(strcmp(argv[1],"list") == 0){
			
				if(strncmp(argv[2] ,"path=", 5) == 0){
					
			        char dir[MAX_PATH_LEN];
			        strcpy(dir, argv[2] + strlen("path="));		
			      
			        printf("SUCCESS\n");
			        listDirContents(dir);

				}else{
					 	if(strncmp(argv[2], "recursive", 9) == 0){
				      
				       		if(strncmp(argv[3] ,"path=", 5) == 0){
				         		//printf("HERE 412\n");
				         		strcpy(dir, argv[3] + 5);
				         		printf("SUCCESS\n");
				         		listDirContentsRecursively(dir);
				         		return 0;
				  			}

				        }else
				         {
				        	if(strncmp(argv[2],"permissions=", 12 ) == 0 ){
				        	
					         	if(strncmp(argv[3] ,"path=",5) == 0){
									
					         		strcpy(permissions, argv[2] + strlen("permissions="));
					         		strcpy(dir, argv[3] + 5);
					         		
					         		printf("SUCCESS\n");
					         		listAllowedFiles(dir,permissions);
					         		return 0;
				         		
					         	}
					        }else{
						          if(strncmp(argv[2],"size_smaller=",13 ) == 0 ){
						    		
						   			   if(strncmp(argv[3] ,"path=", 5) == 0){
						    	
						         		strcpy(dir, argv[3] + 5);	
						        		strcpy(argv[2], argv[2] + strlen("size_smaller="));
						       			f_size = atoi(argv[2]);
						 
						       			printf("SUCCESS\n");
						       			listSizeSmallerFolders(dir,f_size);
						       			return 0;
									}
								}
							}
						}
					//########
					}							
						if(strncmp(argv[4] ,"path=", 5) == 0){
							
							if(strncmp(argv[3],"permissions=",12) == 0 ){
								strcpy(o2, argv[3]);
							}else if(strncmp(argv[2],"permissions=", 12) == 0 ){
								strcpy(o2, argv[2]);
							}else if(strncmp(argv[3],"size_smaller=", 13) == 0 ){
								strcpy(o2, argv[3]);
								}else if(strncmp(argv[2],"size_smaller=", 13) == 0 ){
								strcpy(o2, argv[2]);
							}
								
							if(strncmp(o2, "permissions=", 12) == 0){
								
								if( strcmp(argv[2], "recursive") == 0){
									strcpy(o1, argv[2]);
											
								}else if( strcmp(argv[3], "recursive") == 0){
									strcpy(o1, argv[3]);
												
								}

								strcpy(permissions, o2 + 12);
								strcpy(dir, argv[4] + 5);
							    printf("SUCCESS\n");
							 	listAllowedFilesRecursively(dir,permissions);
							 	return 0;

							}else 
							 	if( strncmp( o2, "size_smaller=", 13) == 0 ){

									if( strcmp(argv[2], "recursive") == 0){
										strcpy(o1, argv[2]);
									}else if( strcmp(argv[3], "recursive") == 0){
										strcpy(o1, argv[3]);
									}	

							        strcpy(o2, o2 + 13);
								       		
							       	f_size = atoi(o2);
							       	//printf("F_SIZE %d\n", f_size);
							        strcpy(dir, argv[4] + 5);
								         		
							        printf("SUCCESS\n");
							  		listSizeSmallerFoldersRecursively(dir,f_size);
							  		return 0;

								}
							}
			
			// PARSE
		  	}else 
			  	{
			  		if(strcmp(argv[1], "parse") == 0){
				  		if(strncmp(argv[2], "path=", 5) == 0){
				  			strcpy(dir, argv[2] + 5);
				  			if((fd1 = isFile(dir)) != 0){
								if(( sectNo = parseFile(fd1, 0) )!= 0){
									showFileDetails(sectNo);
									return 0;
								}
							}	
				  		}
				}else 
					{
		  			if(strcmp(argv[1], "extract") == 0 ){
		   				if(strncmp(argv[2], "path=", 5) == 0){
		  				if(strncmp(argv[3], "section=", 8) == 0) {
		  				if(strncmp(argv[4], "line=", 5) == 0){
						//	printf("--> 571\n");
		  					strcpy(dir, argv[2] + 5);
		  					section = atoi(strcpy(argv[3], argv[3] + 8));
		  					line = atoi( strcpy( argv[4], argv[4] + 5) );
				  				
		  					//printf("SECTION %d LINE %d\n", section, line);
							if((fd1 = isFile(dir)) != 0){
								if(( sectNo = parseFile(fd1, 1) )!= 0){		  							
				  					extractLine(fd1,sectNo, section,line);
				  					return 0;
					  					}
			  						}
			  					}
			  				}
			  			}
			  		}else {
			  			if(strcmp(argv[1], "findall") == 0){
			  				if(strncmp(argv[2], "path=", 5) == 0){
			  					strcpy(dir, argv[2] + 5);
			  					printf("SUCCESS\n");
			  					findAll(dir);
			  				}

			  			} 
			  		}

		  		}
	  		}
		}
	}	
return 0;
}