// Test as executable first for proof of work. #include <windows.h>  //Sleep
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "curl\curl.h"
#include "jsmn.h"

#define GEOIPINFO_FIELDS 14

typedef struct GeoIPInfo {
    char *fields[GEOIPINFO_FIELDS];
} GeoIPInfo;

enum GeoIPInfoIndex {
    STATUS, COUNTRY, COUNTRY_CODE, REGION, REGION_NAME, CITY, ZIP, LAT, LON, TIMEZONE, ISP, ORG, AS, QUERY
};

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

typedef struct string {
    char *ptr;
    size_t len;
} string;
//strndup will throw exception at compile time
char* istrdup(const char* src, size_t n) {
    char* dst=(char*)malloc(n + 1);
    if (dst != NULL) {
        strncpy(dst, src, n);
        dst[n] = '\0';
    }
    return dst;
}

void init_string(string *s) {
    s->len = 0;
    s->ptr = malloc(s->len + 1);
    if (s->ptr == NULL) {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }
    s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, string *s) {
    size_t new_len = s->len + size * nmemb;
    s->ptr = realloc(s->ptr, new_len + 1);
    if (s->ptr == NULL) {
        fprintf(stderr, "realloc() failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size * nmemb;
}
void initIntel(GeoIPInfo *info) {
    for (int i = 0; i < GEOIPINFO_FIELDS; ++i) {
        info->fields[i] = NULL;
    }
}

void setGIPs(GeoIPInfo *info, int index, const char *data, size_t length) {
    info->fields[index] = istrdup(data, length);
}

void cleanGIPs(GeoIPInfo *info) {
    for (int i = 0; i < GEOIPINFO_FIELDS; ++i) {
        free(info->fields[i]);
    }
}


void Intel(const char *ip_address, GeoIPInfo *info) {
    assert(ip_address != NULL && info != NULL);
    assert(strlen(ip_address) <= 39); // IP address size check

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Could not acquire a cURL handle\n");
        return;
    }

    string response;
    init_string(&response);

    char url[62]; // The base URL is 23 characters, and the maximum IP address length is 39 characters for IPv6
    strcpy(url, "http://ip-api.com/json/");
    strcat(url, ip_address);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        free(response.ptr);
        curl_easy_cleanup(curl);
        return;
    }

    curl_easy_cleanup(curl); // Always cleanup

    jsmn_parser json_parser;
    jsmntok_t token_buffer[128]; // We expect no more than 128 JSON tokens

    jsmn_init(&json_parser);
    int r = jsmn_parse(&json_parser, response.ptr, strlen(response.ptr), token_buffer, sizeof(token_buffer) / sizeof(token_buffer[0]));
    if (r < 0) {
        printf("Failed to parse JSON: %d\n", r);
        free(response.ptr);
        return;
    }

    if (r < 1 || token_buffer[0].type != JSMN_OBJECT) {
        printf("Object expected\n");
        free(response.ptr);
        return;
    }
    for (int i = 1; i < r; i++) {
        if (jsoneq(response.ptr, &token_buffer[i], "status") == 0) {
            setGIPs(info, STATUS, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "country") == 0) {
            setGIPs(info, COUNTRY, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "countryCode") == 0) {
            setGIPs(info, COUNTRY_CODE, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "region") == 0) {
            setGIPs(info, REGION, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "regionName") == 0) {
            setGIPs(info, REGION_NAME, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "city") == 0) {
            setGIPs(info, CITY, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "zip") == 0) {
            setGIPs(info, ZIP, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "lat") == 0) {
            setGIPs(info, LAT, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "lon") == 0) {
            setGIPs(info, LON, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "timezone") == 0) {
            setGIPs(info, TIMEZONE, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "isp") == 0) {
            setGIPs(info, ISP, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "org") == 0) {
            setGIPs(info, ORG, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "as") == 0) {
            setGIPs(info, AS, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else if (jsoneq(response.ptr, &token_buffer[i], "query") == 0) {
            setGIPs(info, QUERY, response.ptr + token_buffer[i + 1].start, token_buffer[i + 1].end - token_buffer[i + 1].start);
            i++;
        } else printf("Unexpected key: %.*s\n", token_buffer[i].end - token_buffer[i].start, response.ptr + token_buffer[i].start);
    }
    free(response.ptr);
}
int main() {
    GeoIPInfo info;
    initIntel(&info);
    Intel("8.8.8.8", &info);
    printf("Status: %s\n", info.fields[STATUS]);
    printf("Country: %s\n", info.fields[COUNTRY]);
    printf("countryCode: %s\n", info.fields[COUNTRY_CODE]);
    printf("Region: %s\n", info.fields[REGION]);
    printf("RegionName: %s\n", info.fields[REGION_NAME]);
    printf("City: %s\n", info.fields[CITY]);
    printf("ZIP: %s\n", info.fields[ZIP]);
    printf("Latitude: %s\n", info.fields[LAT]);
    printf("Longitude: %s\n", info.fields[LON]);
    printf("Timezone: %s\n", info.fields[TIMEZONE]);
    printf("ISP: %s\n", info.fields[ISP]);
    printf("ORG: %s\n", info.fields[ORG]);
    printf("ASN: %s\n", info.fields[AS]);
    printf("Query: %s\n", info.fields[QUERY]);

    cleanGIPs(&info);
    // getchar(); Debug
}

// gcc -shared -o cGeoIp.dll cGeoIp.c -IC:\Head -LC:\Lib -lcurl

// Produced and tested by serieuxBlack : https://github.com/serieuxBlack
// Credit to Chase : @cryptio
