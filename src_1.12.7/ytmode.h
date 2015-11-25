#ifndef __YT_MODE_H__
#define __YT_MODE_H__
int OriginalMain(int argc, char *argv[]);
#define MAX_STDIN_ARG_COUNT 32
void DeleteArgV(int *pArgC, char *argV[MAX_STDIN_ARG_COUNT])
{
    for (int i = 0; i < *pArgC; ++i) {
        free(argV[i]);
    }

    *pArgC = 0;
}

static char firstTime = 1;
int ytmodeMain(int argc, char *argv[])
{
    char    stdInStr[MAX_PATH];
    int     pos = 0;
    if (argc == 2 && stricmp(argv[1], "-ytmode") == 0) {
        int     argC = 0;
        char    *argV[MAX_STDIN_ARG_COUNT];
        while (1) {
            scanf("%c", &(stdInStr[pos]));
            if (stdInStr[pos] == '\n' || stdInStr[pos] == '\r') {
                stdInStr[pos] = 0;
                if (!stricmp(stdInStr, "-RUN-")) {
                    OriginalMain(argC, argV);
                    firstTime = 0;
                    DeleteArgV(&argC, argV);
                    printf("-END-");
                    fflush(stdout);
                } else if (!stricmp(stdInStr, "-EXIT-")) {
                    DeleteArgV(&argC, argV);
                    break;
                } else {
                    if (argC >= MAX_STDIN_ARG_COUNT) {
                        DeleteArgV(&argC, argV);
                        printf("[Error] Too many arguments.\n");
                        printf("-ERR-");
                        fflush(stdout);
                    } else {
                        argV[argC] = malloc(pos + 1);
                        strcpy(argV[argC], stdInStr);
                        ++argC;
                    }
                }

                pos = 0;
            } else {
                ++pos;
                if (pos >= MAX_PATH) {
                    DeleteArgV(&argC, argV);
                    pos = 0;
                    printf("[Error] Argument length is too long.\n");
                    printf("-ERR-");
                    fflush(stdout);
                }
            }
        }
//#define __YT_TEST_MODE__
#ifdef __YT_TEST_MODE__
    } else if (stricmp(argv[1], "-ytestText2pcap") == 0) {
        int     argC = 0;
        char    *argV[MAX_STDIN_ARG_COUNT];

        for (int i = 0; i < 2; ++i) {
            argV[argC] = malloc(MAX_PATH); strcpy(argV[argC], "..\\YTshark\\text2pcap.exe"); ++argC;
            argV[argC] = malloc(MAX_PATH); strcpy(argV[argC], "-q");                         ++argC;
            argV[argC] = malloc(MAX_PATH); strcpy(argV[argC], "-l");                         ++argC;
            argV[argC] = malloc(MAX_PATH); strcpy(argV[argC], "147");                        ++argC;
            argV[argC] = malloc(MAX_PATH); strcpy(argV[argC], "Decode.txt");                 ++argC;
            argV[argC] = malloc(MAX_PATH); strcpy(argV[argC], "Decode-tmp.pcap");            ++argC;

            OriginalMain(argC, argV);
            firstTime = 0;
            DeleteArgV(&argC, argV);
        }

        DeleteArgV(&argC, argV);
    } else if (stricmp(argv[1], "-ytestTshark") == 0) {
        int         argC = 0;
        char        *argV[MAX_STDIN_ARG_COUNT];
        const char  *argStr = "uat:user_dlts:\"User 0 (DLT=147)\",\"%s\",\"0\",\"\",\"0\",\"\"";
        for (int i = 0; i < 2; ++i) {
            argV[argC] = malloc(MAX_PATH); strcpy(argV[argC], "..\\YTshark\\tshark.exe"); ++argC;
            argV[argC] = malloc(MAX_PATH); strcpy(argV[argC], "-o");                      ++argC;
            argV[argC] = malloc(MAX_PATH);
            switch (i)
            {
            case 0:
                sprintf(argV[argC], argStr, "lte-rrc.dl.dcch");
                break;

            case 1:
                sprintf(argV[argC], argStr, "lte-rrc.ul.dcch");
                break;
            }

            ++argC;
            argV[argC] = malloc(MAX_PATH); strcpy(argV[argC], "-r");                      ++argC;
            argV[argC] = malloc(MAX_PATH); sprintf(argV[argC], "Decode%d.pcap", i);       ++argC;
            argV[argC] = malloc(MAX_PATH); strcpy(argV[argC], "-V");                      ++argC;

            OriginalMain(argC, argV);
            firstTime = 0;
            DeleteArgV(&argC, argV);
        }

        DeleteArgV(&argC, argV);
#endif
    } else {
        return OriginalMain(argc, argv);
    }

    return 0;
}

#endif
