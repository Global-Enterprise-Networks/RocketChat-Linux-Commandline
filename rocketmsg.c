#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <unistd.h>

#define MAX_LINE_LENGTH 256
#define CONFIG_FILE ".rocketmsg.conf"

const char *VERSION = "1.012(RT109)";
const char *USAGE = "Usage: %s [-h] [-q] [-d] [-c configfile] -r room/team/channel [-m message] [-a attachment_path]\n";

struct MemoryStruct
{
    char *memory;
    size_t size;
};


char *trim(char *str) {
    char *end;
    while (isspace((unsigned char)*str))
        str++;
    if (*str == 0)
        return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;
    *(end + 1) = 0;
    return str;
}

char *url_encode(const char *str) {
    const char *hex = "0123456789abcdef";
    size_t len = strlen(str);
    char *encoded = (char *)malloc(len * 3 + 1); // Allocate enough memory for the worst case
    char *p = encoded;

    for (; *str; str++)
    {
        if (isalnum(*str) || *str == '-' || *str == '_' || *str == '.' || *str == '~')
        {
            *p++ = *str;
        }
        else
        {
            *p++ = '%';
            *p++ = hex[*str >> 4];
            *p++ = hex[*str & 15];
        }
    }

    *p = '\0';
    return encoded;
}

const char *get_mime_type(const char *filename) {
    const char *ext = strrchr(filename, '.');
    if (ext == NULL)
        return "application/octet-stream";

    if (strcmp(ext, ".txt") == 0)
        return "text/plain";
    else if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0)
        return "text/html";
    else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0)
        return "image/jpeg";
    else if (strcmp(ext, ".png") == 0)
        return "image/png";
    else if (strcmp(ext, ".gif") == 0)
        return "image/gif";
    else if (strcmp(ext, ".wav") == 0)
        return "audio/wav";
    else if (strcmp(ext, ".mp3") == 0)
        return "audio/mpeg";
    else
        return "application/octet-stream";
}

char *base64_encode(const unsigned char *data, size_t input_length) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(output_length + 1);
    if (encoded_data == NULL)
    {
        return NULL;
    }

    for (size_t i = 0, j = 0; i < input_length;)
    {
        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }

    for (size_t i = 0; i < (3 - input_length % 3) % 3; i++)
    {
        encoded_data[output_length - 1 - i] = '=';
    }

    encoded_data[output_length] = '\0';
    return encoded_data;
}

/**
 * Callback function to handle writing data to memory.
 * Allocates/reallocs memory as needed and copies the data into
 * the memory struct.
 *
 * @param contents Data being written.
 * @param size Size of each element being written.
 * @param nmemb Number of elements being written.
 * @param userp Pointer to the MemoryStruct to write to.
 * @return Number of bytes actually written.
 */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL)
    {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}


char *read_message_from_stdin() {
    char *message = NULL;
    size_t size = 0;
    size_t capacity = 0;
    char buffer[4096];

    while (fgets(buffer, sizeof(buffer), stdin) != NULL)
    {
        size_t len = strlen(buffer);
        if (size + len + 1 > capacity)
        {
            capacity = (size + len + 1) * 2;
            char *new_message = realloc(message, capacity);
            if (new_message == NULL)
            {
                free(message);
                return NULL;
            }
            message = new_message;
        }
        memcpy(message + size, buffer, len);
        size += len;
    }

    if (message != NULL)
    {
        message[size] = '\0';
    }

    return message;
}

char *json_escape_string(const char *str) {
    if (str == NULL)
        return NULL;

    size_t len = strlen(str);
    size_t escaped_len = 0;
    for (size_t i = 0; i < len; i++)
    {
        switch (str[i])
        {
        case '\\':
        case '"':
            escaped_len += 2;
            break;
        default:
            escaped_len++;
            break;
        }
    }

    char *escaped_str = malloc(escaped_len + 1);
    if (escaped_str == NULL)
        return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++)
    {
        switch (str[i])
        {
        case '\\':
            escaped_str[j++] = '\\';
            escaped_str[j++] = '\\';
            break;
        case '"':
            escaped_str[j++] = '\\';
            escaped_str[j++] = '"';
            break;
        default:
            escaped_str[j++] = str[i];
            break;
        }
    }
    escaped_str[j] = '\0';

    return escaped_str;
}


void var_dump(void *var, char type) {
    switch (type) {
        case 'i':
            printf("Integer: %d\n", *(int *)var);
            break;
        case 'f':
            printf("Float: %f\n", *(float *)var);
            break;
        case 'c':
            printf("Char: '%c' (ASCII: %d)\n", *(char *)var, *(char *)var);
            break;
        case 's':
            printf("String: \"");
            for (char *p = (char *)var; *p != '\0'; p++) {
                if (*p == '\0')
                    printf("\\0");
                else
                    putchar(*p);
            }
            printf("\\0\" (Length including null terminator: %zu)\n", strlen((char *)var) + 1);
            break;
        case 'p':
            printf("Pointer: %p\n", *(void **)var);
            break;
        default:
            printf("Unknown type\n");
    }
}

int main(int argc, char *argv[]) {
    fprintf(stderr, "RocketMSG Version %s\n", VERSION);

    char *USERNAME = "";
    char *PASSWORD = "";
    char *SERVER_URL = "";
    char *CONFIGFILE = NULL;
    char config_file_path[255];

    //FILE *file;
    const char *home_dir = getenv("HOME");

    char *room = NULL;
    char *message = NULL;
    char *attachment_path = NULL;
    int mention_all = 0;
    int quoted_mode = 0;
    int debug =0;

    int opt;
    while ((opt = getopt(argc, argv, "c:r:m:a:qdh")) != -1) {
        switch (opt) {
            case 'c':
                //CONFIGFILE = malloc(strlen(optarg) + 1);
                //strcpy(CONFIGFILE, optarg);   
                CONFIGFILE = optarg;          
            case 'r':
                room = optarg;
                break;
            case 'm':
                message = optarg;
                break;
            case 'a':
                attachment_path = optarg;
                break;
            case 'q':
                quoted_mode = 1;
                break;
            case 'd':
                debug = 1;
                break;
            case 'h':
                fprintf(stderr, USAGE, argv[0]);
                fprintf(stderr, "\n-d : Debug mode\n"
                "-q : Quoted mode\n"
                "-r : Target, such as @Fred, #General or MyTeam\n"
                "-a : Attachment (text, image, video or audio file)\n"
                "-m : Message OR if not used, STDIN\n\n"
                "-c : Configuration file location (if not ~/.rocketmsg.conf)\nFor more information see https://support.gen.uk/scp/faq.php?cid=33\n");
                exit(EXIT_FAILURE);
            default:
                fprintf(stderr, USAGE, argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if(room == NULL) {
        fprintf(stderr, USAGE, argv[0]);
        exit(EXIT_FAILURE);       
    }

    if (CONFIGFILE != NULL) {
        if (access(CONFIGFILE, F_OK) == 0) {
            FILE *file = fopen(CONFIGFILE, "r");
            if (file == NULL) {
                fprintf(stderr, "File %s could not be opened\n", CONFIGFILE);
                exit(EXIT_FAILURE);
            } else {
                char line[MAX_LINE_LENGTH];
                while (fgets(line, sizeof(line), file))
                {
                    char key[MAX_LINE_LENGTH], value[MAX_LINE_LENGTH];
                    if (sscanf(line, "%s = %[^\n]", key, value) == 2) {
                        for (char *p = key; *p; ++p) *p = tolower(*p);
                        char *trimmed_value = trim(value);
                        if (debug) {
                            fprintf(stderr, "key: %s value: %s\n", key, trimmed_value);
                        }
                        if (strcmp(key, "serverurl") == 0) {
                            SERVER_URL = malloc(strlen(trimmed_value) + 1);
                            strcpy(SERVER_URL, trimmed_value);
                        } else if (strcmp(key, "username") == 0) {
                            USERNAME = malloc(strlen(trimmed_value) + 1);
                            strcpy(USERNAME, trimmed_value);
                        } else if (strcmp(key, "password") == 0) {
                            PASSWORD = malloc(strlen(trimmed_value) + 1);
                            strcpy(PASSWORD, trimmed_value);
                        }
                    }
                }
                fclose(file);                
            }    
        } else {
            fprintf(stderr, "File %s could not be found\n", CONFIGFILE);
            exit(EXIT_FAILURE);
        }
    } else {
        if (home_dir == NULL) {
            perror("Failed to get home directory");
            exit(EXIT_FAILURE);
        }

        snprintf(config_file_path, sizeof(config_file_path), "%s/%s", home_dir, CONFIG_FILE);
        FILE *file = fopen(config_file_path, "r");
        if (file == NULL) {
            fprintf(stderr, "File %s could not be opened\n", CONFIGFILE);
            exit(EXIT_FAILURE);
        } else {
            char line[MAX_LINE_LENGTH];
            while (fgets(line, sizeof(line), file))
            {
                char key[MAX_LINE_LENGTH], value[MAX_LINE_LENGTH];
                if (sscanf(line, "%s = %[^\n]", key, value) == 2) {
                    for (char *p = key; *p; ++p) *p = tolower(*p);
                    char *trimmed_value = trim(value);
                    if (debug) {
                        fprintf(stderr, "key: %s value: %s\n", key, trimmed_value);
                    }
                    if (strcmp(key, "serverurl") == 0) {
                        SERVER_URL = malloc(strlen(trimmed_value) + 1);
                        strcpy(SERVER_URL, trimmed_value);
                    } else if (strcmp(key, "username") == 0) {
                        USERNAME = malloc(strlen(trimmed_value) + 1);
                        strcpy(USERNAME, trimmed_value);
                    } else if (strcmp(key, "password") == 0) {
                        PASSWORD = malloc(strlen(trimmed_value) + 1);
                        strcpy(PASSWORD, trimmed_value);
                    }
                }
            }
            fclose(file);
        }
    }

    if (optind < argc) {
        message = malloc(strlen(argv[optind]) + 1);
        strcpy(message, argv[optind]);
        for (int i = optind + 1; i < argc; i++) {
            message = realloc(message, strlen(message) + strlen(argv[i]) + 2);
            strcat(message, " ");
            strcat(message, argv[i]);
        }
    }

    if(message == NULL) {
        message = read_message_from_stdin();
        if (message == NULL) {
            fprintf(stderr, "Failed to read message from stdin\n");
            return 1;
        }
    }

    if (room == NULL) {
        fprintf(stderr, USAGE, argv[0]);
        exit(EXIT_FAILURE);
    }


    if (debug) {
        if(CONFIGFILE==NULL) {
            printf("Config File: %s\n", config_file_path);
        } else {
            printf("Config File: %s\n", CONFIGFILE);
        }
        printf("SERVER_URL: %s\n",SERVER_URL);
        printf("USERNAME: %s\n",USERNAME);
        printf("PASSWORD: %s\n",PASSWORD);
    }

    if (strlen(SERVER_URL) == 0 || strlen(USERNAME) == 0 || strlen(PASSWORD) == 0) {  
        fprintf(stderr, "Missing configuration\n");
        exit(EXIT_FAILURE);
    }

    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl)
    {
        struct MemoryStruct chunk;
        chunk.memory = malloc(1);
        chunk.size = 0;

        char authUrl[256];
        snprintf(authUrl, sizeof(authUrl), "%s/api/v1/login", SERVER_URL);

        char authPayload[256];
        snprintf(authPayload, sizeof(authPayload), "{\"username\":\"%s\",\"password\":\"%s\"}", USERNAME, PASSWORD);

        struct curl_slist *authHeaders = NULL;
        authHeaders = curl_slist_append(authHeaders, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, authUrl);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, authPayload);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, authHeaders);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        else
        {
            // Parse the response to extract the user ID and token
            json_object *jsonResponse = json_tokener_parse(chunk.memory);
            if (jsonResponse == NULL)
            {
                fprintf(stderr, "Failed to parse JSON response.\n");
            }
            else
            {
                json_object *jsonData = json_object_object_get(jsonResponse, "data");
                if (jsonData == NULL)
                {
                    fprintf(stderr, "Failed to get 'data' object from JSON response.\n");
                }
                else
                {
                    const char *userId = json_object_get_string(json_object_object_get(jsonData, "userId"));
                    const char *authToken = json_object_get_string(json_object_object_get(jsonData, "authToken"));

                    if (userId && authToken)
                    {

                        free(chunk.memory);
                        chunk.memory = malloc(1);
                        chunk.size = 0;

                        char url[256];
                        snprintf(url, sizeof(url), "%s/api/v1/chat.postMessage", SERVER_URL);

                        char *escaped_message = json_escape_string(message);
                        char *formatted_message = NULL;
                        if (quoted_mode) {
                            size_t formatted_message_length = strlen(escaped_message) + 9;
                            formatted_message = malloc(formatted_message_length);
                            snprintf(formatted_message, formatted_message_length, "```\n%s\n```", escaped_message);
                        } else {
                            formatted_message = strdup(escaped_message);
                        }

                        json_object *payload = json_object_new_object();
                        json_object_object_add(payload, "channel", json_object_new_string(room));
                        json_object_object_add(payload, "text", json_object_new_string(formatted_message));

                        if (attachment_path != NULL) {
                            FILE *file = fopen(attachment_path, "rb");
                            if (file != NULL) {
                                fseek(file, 0, SEEK_END);
                                size_t file_size = (size_t)ftell(file);
                                fseek(file, 0, SEEK_SET);

                                char *file_content = malloc(file_size);
                                if (file_content != NULL) {
                                    size_t bytes_read = fread(file_content, 1, file_size, file);
                                    if (bytes_read == file_size) {
                                        char *encoded_content = base64_encode((const unsigned char *)file_content, file_size);
                                        if (encoded_content != NULL) {
                                            json_object *attachment = json_object_new_object();

                                            const char *filename = strrchr(attachment_path, '/');
                                            if (filename == NULL)
                                                filename = attachment_path;
                                            else
                                                filename++;

                                            json_object_object_add(attachment, "title", json_object_new_string(filename));

                                            const char *mime_type = get_mime_type(attachment_path);
                                            if (strncmp(mime_type, "image/", 6) == 0) {
                                                json_object_object_add(attachment, "type", json_object_new_string("image"));
                                                char *image_url = malloc(strlen("data:") + strlen(mime_type) + strlen(";base64,") + strlen(encoded_content) + 1);
                                                sprintf(image_url, "data:%s;base64,%s", mime_type, encoded_content);
                                                json_object_object_add(attachment, "image_url", json_object_new_string(image_url));
                                                free(image_url);
                                            } else if (strncmp(mime_type, "audio/", 6) == 0) {
                                                json_object_object_add(attachment, "type", json_object_new_string("audio"));
                                                char *audio_url = malloc(strlen("data:") + strlen(mime_type) + strlen(";base64,") + strlen(encoded_content) + 1);
                                                sprintf(audio_url, "data:%s;base64,%s", mime_type, encoded_content);
                                                json_object_object_add(attachment, "audio_url", json_object_new_string(audio_url));
                                                free(audio_url);
                                            } else if (strncmp(mime_type, "video/", 6) == 0) {
                                                json_object_object_add(attachment, "type", json_object_new_string("video"));
                                                char *video_url = malloc(strlen("data:") + strlen(mime_type) + strlen(";base64,") + strlen(encoded_content) + 1);
                                                sprintf(video_url, "data:%s;base64,%s", mime_type, encoded_content);
                                                json_object_object_add(attachment, "video_url", json_object_new_string(video_url));
                                                free(video_url);
                                            } else {
                                                json_object_object_add(attachment, "type", json_object_new_string("text"));
                                                //char *text = malloc(strlen("data:") + strlen(mime_type) + strlen(";base64,") + strlen(encoded_content) + 1);
                                                //sprintf(text, "data:%s;base64,%s", mime_type, encoded_content);
                                                json_object_object_add(attachment, "text", json_object_new_string(file_content));
                                                //free(text);
                                            }

                                            json_object *attachments = json_object_new_array();
                                            json_object_array_add(attachments, attachment);

                                            json_object_object_add(payload, "attachments", attachments);

                                            free(encoded_content);
                                        }
                                    } else {
                                        fprintf(stderr, "Error reading attachment file: %s\n", attachment_path);
                                    }
                                    free(file_content);
                                } else {
                                    fprintf(stderr, "Memory allocation failed for attachment file content\n");
                                }
                                fclose(file);
                            } else {
                                fprintf(stderr, "Cannot read attachment: %s\n", attachment_path);
                            }
                        }

                        if (debug) {
                            printf("JSON Payload:\n");
                            printf("%s\n", json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PRETTY));
                        }
                        const char *json_payload = json_object_to_json_string(payload);

                        struct curl_slist *headers = NULL;
                        headers = curl_slist_append(headers, "Content-Type: application/json");

                        char authTokenHeader[256];
                        snprintf(authTokenHeader, sizeof(authTokenHeader), "X-Auth-Token: %s", authToken);
                        headers = curl_slist_append(headers, authTokenHeader);

                        char userIdHeader[256];
                        snprintf(userIdHeader, sizeof(userIdHeader), "X-User-Id: %s", userId);
                        headers = curl_slist_append(headers, userIdHeader);

                        curl_easy_setopt(curl, CURLOPT_URL, url);
                        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
                        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

                        res = curl_easy_perform(curl);
                        if (res != CURLE_OK) {
                            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                        } else {
                            // Parse the response to check if the message was posted successfully
                            json_object *postResponse = json_tokener_parse(chunk.memory);
                            if (postResponse == NULL)
                            {
                                fprintf(stderr, "Failed to parse JSON response.\n");
                            }
                            else
                            {
                                json_object *success = json_object_object_get(postResponse, "success");
                                if (success == NULL || !json_object_get_boolean(success))
                                {
                                    json_object *error = json_object_object_get(postResponse, "error");
                                    if (error != NULL)
                                    {
                                        const char *errorMessage = json_object_get_string(error);
                                        fprintf(stderr, "Failed to post message. Error: %s\n", errorMessage);
                                    }
                                    else
                                    {
                                        fprintf(stderr, "Failed to post message. Unknown error.\n");
                                        fprintf(stderr, "Response: %s\n", chunk.memory);
                                    }
                                }
                                else
                                {
                                    printf("Message posted successfully.\n");
                                }

                                json_object_put(postResponse);
                            }
                        }
                        curl_slist_free_all(headers);
                        json_object_put(payload);
                        free(formatted_message);
                        free(escaped_message);
                    } else {
                        fprintf(stderr, "Failed to extract user ID and auth token from the response.\n");
                    }
                }
                json_object_put(jsonResponse);
            }
        }
        free(chunk.memory);
        curl_slist_free_all(authHeaders);
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    free(SERVER_URL);
    free(USERNAME);
    free(PASSWORD);

    return 0;
}
