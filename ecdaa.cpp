#include<iostream>
#include<cstring>
#include<tss2/tss2_esys.h>
#include<gmp.h>
#include<openssl/sha.h>
#include<pbc/pbc.h>
#include<time.h>
// #include"amcl/amcl.h"
#define J "test"


using namespace std;

void commit(ESYS_CONTEXT *esys_context, TPM2B_ECC_POINT *P1, TPM2B_ECC_POINT **K, TPM2B_ECC_POINT **L, TPM2B_ECC_POINT **E, const char *j, UINT16 *counter, ESYS_TR *eccHandle, ESYS_TR *session, int flag);
void ECC_point_to_str(TPM2B_ECC_POINT *P, char *s);
void h2(const char *m, TPM2B_SENSITIVE_DATA *s, TPM2B_ECC_PARAMETER *y);
void bsn_to_point(const char *m2, char *s2, char *x2, char *y2);
void byte_to_char(unsigned char *md, char *s, int size=32);
void char_to_byte(char *s, BYTE *bytes);
void create_issuer_key(pairing_t pairing, element_t *x, element_t *y, element_t *X, element_t *Y, element_t P1, element_t P2);
int join_verify(unsigned char *signatureS, unsigned char *hash_res, unsigned char *signatureR, element_t P1, element_t Q1, pairing_t pairing, char *str0);
void issuer_make_cred(pairing_t pairing, element_t P1, element_t Q1, element_t *A, element_t *B, element_t *C, element_t *D, element_t x, element_t y);
int check_cred(pairing_t pairing, element_t P1, element_t P2, element_t A, element_t B, element_t C, element_t D, element_t X, element_t Y);
void rand_cred(pairing_t pairing, element_t A, element_t B, element_t C, element_t D, element_t *R, element_t *S, element_t *T, element_t *W);
void element_to_ECCPoint(element_t e, TPM2B_ECC_POINT *P1);
int verify(pairing_t pairing, element_t R, element_t S, element_t T, element_t W, element_t X, element_t Y, element_t P2, unsigned char *signatureS, unsigned char *hash_res, unsigned char *signatureR, char *k);
void bsn_to_element(element_t *J2);



int main(){
    clock_t start, end;
    start = clock();
    ESYS_CONTEXT *esys_context = NULL;
    TSS2_RC rc = Esys_Initialize(&esys_context, NULL, NULL);
    TSS2_RC r;
    ESYS_TR eccHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;

    // 初始化createprimary函数相关的参数
    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 },
        .mode = {.aes = TPM2_ALG_CFB}
    };

    TPMA_SESSION sessionAttributes;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    memset(&sessionAttributes, 0, sizeof sessionAttributes);
    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                              &session);

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0}
             },
            .data = {
                 .size = 0,
                 .buffer = {0}
             }
        }
    };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters = {
                .eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                     .keyBits = {.aes = 128},
                     .mode = {.aes = TPM2_ALG_CFB},
                 },
                 .scheme = {
                      .scheme = TPM2_ALG_ECDAA,
                      .details = {.ecdaa = {.hashAlg = TPM2_ALG_SHA256, .count = 1}
                      }
                  },
                 .curveID = TPM2_ECC_BN_P256,
                 .kdf = {.scheme = TPM2_ALG_NULL }
                }
             },
             .unique = {
                .ecc = {
                    .x = {.size = 32,.buffer = {0}},
                    .y = {.size = 32,.buffer = {0}}
                }
             },
        }
    };

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {}
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    // 生成公私钥对
    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, session,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublic,
                           &outsideInfo, &creationPCR, &eccHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    TPM2B_ECC_POINT ecc_P1 = {0};
    ecc_P1.point.x.buffer[31] = 1;
    ecc_P1.point.y.buffer[31] = 2;
    TPM2B_ECC_POINT *K = NULL;
    TPM2B_ECC_POINT *L = NULL;
    TPM2B_ECC_POINT *E = NULL;
    TPM2B_ECC_POINT Q;

    // Q = [sk]P1
    Q.point = outPublic->publicArea.unique.ecc;

    UINT16 counter;

    /*
     * commit:
     * 生成随机数r
     * K = [sk](x, y)
     * L = [r](x, y)
     * E = [r]P1
     * 其中x为能生成该点横坐标值的字符串，y为椭圆曲线上一点的纵坐标值（计算方法在h2函数中）
     */
    commit(esys_context, &ecc_P1, &K, &L, &E, J, &counter, &eccHandle, &session, 0);

    // 初始化双线性匹配相关的参数
    pairing_t pairing;
    element_t P1, P2, Q1, x, y, X, Y, A, B, C, D;
    char P2_str[500];
    char s[] = "type f q 115792089237314936872688561244471742058375878355761205198700409522629664518163 r 115792089237314936872688561244471742058035595988840268584488757999429535617037 b 3 beta -2 alpha0 1 alpha1 1";
    pairing_init_set_str(pairing, s);

    element_init_G1(P1, pairing);
    element_init_G1(Q1, pairing);
    element_init_G1(A, pairing);
    element_init_G1(B, pairing);
    element_init_G1(C, pairing);
    element_init_G1(D, pairing);

    element_init_G2(P2, pairing);
    element_init_G2(Y, pairing);
    element_init_G2(X, pairing);

    element_init_Zr(x, pairing);
    element_init_Zr(y, pairing);

    element_set_str(P1, "[1, 2]", 10);
    element_random(P2);
    create_issuer_key(pairing, &x, &y, &X, &Y, P1, P2);


    char sss[500]="";
    char str[2000] = "";
    char str0[1000] = "";

    // 生成要签名的字符串并计算其hash值
    ECC_point_to_str(&ecc_P1, sss);
    strcat(str, sss);
    ECC_point_to_str(&Q, sss);
    strcat(str, sss);
    element_set_str(Q1, sss, 10);
    // cout<<"Q: "<<sss<<endl;
    ECC_point_to_str(E, sss);
    // cout<<"U: "<<sss<<endl;
    strcat(str, sss);
    element_snprint(sss, 512, X);
    strcat(str0, sss);
    element_snprint(sss, 512, Y);
    strcat(str0, sss);
    strcat(str0, "1");
    strcat(str, str0);
    // cout<<"str: "<<str<<endl;

    unsigned char hash_res[32], signatureS[32], signatureR[32];
    SHA256((unsigned char*)str, strlen(str), hash_res);
    byte_to_char(hash_res, sss);
    // cout<<"hash result: "<<sss<<endl;

    // 初始化sign函数相关的参数
    TPM2B_DIGEST digest;
    memcpy(digest.buffer, hash_res, 32);
    digest.size = 32;

    TPMT_SIG_SCHEME inScheme;
    inScheme.scheme = TPM2_ALG_ECDAA;
	inScheme.details.ecdaa.hashAlg = TPM2_ALG_SHA256;
	inScheme.details.ecdaa.count = counter;
    

    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_OWNER,
        .digest = {0}
    };
    TPMT_SIGNATURE *signature = NULL;

    /*
     * sign函数:
     * 生成随机数k
     * T = H(k||v)(mod n)  (H为指定的hash算法 这里是sha256）
     * 签名s = r + T * sk (mod q)
     * 其中r为之前commit操作生成的随机数，v为生成的hash值
     * 返回（k，s）
     */
    Esys_Sign(esys_context, eccHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, &digest, &inScheme, &hash_validation, &signature);
    // cout<<signature->signature.ecdaa.signatureR.size<<endl<<signature->sigAlg<<endl;
    memcpy(signatureR, signature->signature.ecdaa.signatureR.buffer, 32);
    memcpy(signatureS, signature->signature.ecdaa.signatureS.buffer, 32);

    /*
     * 这里验证应该由issuer进行
     * 将点Q、hash值v、签名值s、新鲜值等参数发送给issuer进行验证
     */
    int ret = join_verify(signatureS, hash_res, signatureR, P1, Q1, pairing, str0);

    if(ret!=0){
        cout<<"sk error"<<endl;
        return 0;
    }
    cout<<"check sk success"<<endl;

    cout<<"issuer make credential: "<<endl;
    issuer_make_cred(pairing, P1, Q1, &A, &B, &C, &D, x, y);
    element_snprint(sss, 256, A);
    cout<<"A: "<<sss<<endl;
    element_snprint(sss, 256, B);
    cout<<"B: "<<sss<<endl;
    element_snprint(sss, 256, C);
    cout<<"C: "<<sss<<endl;
    element_snprint(sss, 256, D);
    cout<<"D: "<<sss<<endl;
    ret = check_cred(pairing, P1, P2, A, B, C, D, X, Y);
    if(ret!=1){
        return 0;
    }
    cout<<"check credential success"<<endl;

    element_t R, S, T, W;
    element_init_G1(R, pairing);
    element_init_G1(S, pairing);
    element_init_G1(T, pairing);
    element_init_G1(W, pairing);

    // 随机化证书
    rand_cred(pairing, A, B, C, D, &R, &S, &T, &W);
    cout<<"make random credential"<<endl;

    element_to_ECCPoint(S, &ecc_P1);
    ecc_P1.point.x.size = 32;
    ecc_P1.point.y.size = 32;
    // ECC_point_to_str(&ecc_P1, sss);
    // cout<<"S: "<<sss<<endl;
    // 再次进行commit为签名做准备
    commit(esys_context, &ecc_P1, &K, &L, &E, J, &counter, &eccHandle, &session, 1);

    // 将相关的值、msg等进行拼接字符串并计算hash
    element_snprint(sss, 256, R);
    cout<<"R: "<<sss<<endl;
    strcpy(str, sss);
    element_snprint(sss, 256, S);
    cout<<"S: "<<sss<<endl;
    strcat(str, sss);
    element_snprint(sss, 256, T);
    cout<<"T: "<<sss<<endl;
    strcat(str, sss);
    element_snprint(sss, 256, W);
    cout<<"W: "<<sss<<endl;
    strcat(str, sss);
    strcat(str, "2");
    SHA256((unsigned char*)str, strlen(str), hash_res);
    byte_to_char(hash_res, str0, 32);
    strcpy(str, str0);
    char msg[] = "1234567";
    strcat(str, msg);
    ECC_point_to_str(K, sss);
    strcat(str, sss);
    // cout<<"K: "<<sss<<endl;
    ECC_point_to_str(L, sss);
    strcat(str, sss);
    // cout<<"L: "<<sss<<endl;
    ECC_point_to_str(E, sss);
    strcat(str, sss);
    // cout<<"E: "<<sss<<endl;
    strcat(str, J);
    strcat(str, "3");

    // cout<<str<<endl;

    SHA256((unsigned char*)str, strlen(str), hash_res);
    memcpy(digest.buffer, hash_res, 32);

    // signature = NULL;
	inScheme.details.ecdaa.count = counter;
	// 签名
    Esys_Sign(esys_context, eccHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, &digest, &inScheme, &hash_validation, &signature);

    // memcpy(signatureS, signature->signature.ecdaa.signatureS, 32);
    memcpy(signatureR, signature->signature.ecdaa.signatureR.buffer, 32);
    memcpy(signatureS, signature->signature.ecdaa.signatureS.buffer, 32);
    ECC_point_to_str(K, sss);

    /*
     * 将R、S、T、W、J、K、hash值、签名s、msg、新鲜值等传递给verifier
     * 由verifier进行验证
     */
    ret = verify(pairing, R, S, T, W, X, Y, P2, signatureS, hash_res, signatureR, sss);
    if(ret){
        cout<<"error"<<endl;
        return 0;
    }
    cout<<"check success"<<endl;
    end = clock();
    cout<<(double)(end-start)/CLOCKS_PER_SEC<<endl;
    
}

/*
 * 对tpm的commit函数进行了简单的包装
 */
void commit(ESYS_CONTEXT *esys_context, TPM2B_ECC_POINT *P1, TPM2B_ECC_POINT **K, TPM2B_ECC_POINT **L, TPM2B_ECC_POINT **E, const char *j, UINT16 *counter, ESYS_TR *eccHandle, ESYS_TR *session, int flag){
    TSS2_RC r;
    TPM2B_SENSITIVE_DATA s2={0};
    TPM2B_ECC_PARAMETER y2={0};

    if(flag==1) h2(j, &s2, &y2);
    r = Esys_Commit(esys_context, *eccHandle,
                    *session, ESYS_TR_NONE, ESYS_TR_NONE,
                    P1, &s2, &y2,
                    K, L, E, counter);
}

/*
 * 用于将TPM生成的点转为[x, y]形式的字符串（十进制）
 */
void ECC_point_to_str(TPM2B_ECC_POINT *P, char *s) 
{
    mpz_t x, y, temp, h;
    mpz_init_set_si(h, 256);
    mpz_init_set_si(x, 0);
    mpz_init_set_si(y, 0);
    strcpy(s, "");

    char *str_temp;
    // cout<<'w'<<endl;

    for(int i = 0; i<32; i++){
        // cout<<int(P->point.x.buffer[i])<<endl;
        mpz_init_set_si(temp, int(P->point.x.buffer[i]));
        mpz_mul(x, x, h);
        mpz_add(x, x, temp);

        mpz_init_set_si(temp, int(P->point.y.buffer[i]));
        mpz_mul(y, y, h);
        mpz_add(y, y, temp);

    }
    strcat(s, "[");
    str_temp = mpz_get_str(NULL, 10, x);
    strcat(s, str_temp);
    strcat(s, ", ");

    mpz_get_str(str_temp, 10, y);
    strcat(s, str_temp);
    strcat(s, "]");
    // cout<<s<<endl;

    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(temp);
    mpz_clear(h);
}

/*
 * 将调用bsn_to_point函数生成的点转为commit函数要用到的TPM2B_SENSITIVE_DATA和TPM2B_ECC_PARAMETER格式
 */
void h2(const char *m2, TPM2B_SENSITIVE_DATA *s2, TPM2B_ECC_PARAMETER *y2){
    BYTE bytes[32];
    char s[300], x[300], y[300];
    bsn_to_point(m2, s, x, y);
    
    // cout<<y<<endl;
    // cout<<x<<endl;
    // cout<<s<<endl;

    char_to_byte(y, bytes);
    memcpy(y2->buffer, bytes, 32);
    y2->size = 32;
    s2->size = strlen(s);
    memcpy(s2->buffer, s, strlen(s));
}

/*
 * 将一个任意的字符串映射到椭圆曲线上的一点，利用到了二次剩余
 */
void bsn_to_point(const char *m2, char *s2, char *x2, char *y2)
{
    unsigned char temp[64];
    int result = -1;
    char *s;
    mpz_t x, q, right, y, temp1, temp2, i;
    mpz_init_set_str(q, "115792089237314936872688561244471742058375878355761205198700409522629664518163", 10);

    mpz_init_set_si(i, 0);
    mpz_init_set_si(temp1, 0);
    mpz_init_set_si(right, 0);
    mpz_init_set_si(temp2, 0);
    mpz_init_set_si(y, 0);

    do{
        s = mpz_get_str(NULL, 10, i);
        strcpy(s2, m2);
        strcat(s2, s);
        SHA256((unsigned char*)s2, strlen(s2), temp);
        byte_to_char(temp, x2, 32);
        mpz_init_set_str(x, x2, 16);
        mpz_powm_ui(temp1, x, 3, q);
        mpz_add_ui(right, temp1, 3);

        mpz_sub_ui(temp1, q, 1);
        mpz_cdiv_qr_ui(temp1, temp2, temp1, 2);
        if(mpz_cmp_si(temp2, 0)!=0) cout<<"(p-1)//2 error"<<endl;
        mpz_powm(temp1, right, temp1, q);
        
        result = mpz_cmp_si(temp1, 1);
        mpz_add_ui(i, i, 1);

    }while (result!=0);

    mpz_add_ui(temp1, q, 1);

    mpz_cdiv_qr_ui(temp1, temp2, temp1, 4);
    if(mpz_cmp_si(temp2, 0)!=0) cout<<"(p+1)//4 error"<<endl;
    mpz_powm(y, right, temp1, q);
    
    // cout<<"x: "<<x2<<endl;
    s = mpz_get_str(NULL, 16, y);
    strcpy(y2, s);
    // cout<<"y: "<<y2<<endl;
    
    mpz_clear(x);
    mpz_clear(q);
    mpz_clear(right);
    mpz_clear(y);
    mpz_clear(temp2);
    mpz_clear(temp1);
    mpz_clear(i);

}

/*
 * 将字节串转为十六进制字符串
 */
void byte_to_char(unsigned char *md, char *s, int size)
{
    char temp;
    for(int i=0;i<size;i++){
        temp = (md[i]&0xf0)>>4;
        if(temp>9) temp += 39;
        s[i*2] = temp+48;
        temp = md[i]&0x0f;
        if(temp>9) temp += 39;
        s[i*2+1] = temp+0x30;
    }
    s[size*2] = '\0';
}


/*
 * 将十六进制字符串转为字节串
 */
void char_to_byte(char *s, BYTE *bytes)
{
    int b = 0, t;
    BYTE temp1, temp2;
    for(int i=0;i<strlen(s);i+=2){
        temp1 = s[i]|32;
        temp2 = s[i+1]|32;

        temp1 = (temp1>='a'&temp1<='f')?temp1-39:temp1;
        temp2 = (temp2>='a'&temp2<='f')?temp2-39:temp2;

        bytes[b] = ((temp1&~0x30)<<4)|(temp2&~0x30);
        b++;
    }
}


/*
 * issuer生成公私钥
 */
void create_issuer_key(pairing_t pairing, element_t *x, element_t *y, element_t *X, element_t *Y, element_t P1, element_t P2)
{   element_random(*x);
    element_random(*y);

    element_pow_zn(*X, P2, *x);
    element_pow_zn(*Y, P2, *y);
}

/*
 * 由issuer验证加入时的签名
 */
int join_verify(unsigned char *signatureS, unsigned char *hash_res, unsigned char *signatureR, element_t P1, element_t Q1, pairing_t pairing, char *str0){
    char temp[1000], sss[300];
    unsigned char v[32], bytes[32];
    mpz_t gmp_temp;

    SHA256_CTX h;
    // byte_to_char(signatureR, sss, 32);
    // cout<<"k: "<<sss<<endl;
    // byte_to_char(hash_res, sss, 32);
    // cout<<"p: "<<sss<<endl;

    /*
     * 计算v = H（r||hash_res)(mod n)
     */
    SHA256_Init(&h);
    SHA256_Update(&h, signatureR, 32);
    SHA256_Update(&h, hash_res, 32);
    SHA256_Final(v, &h);

    element_t W, V, t1, t2, U;

    element_init_Zr(W, pairing);
    byte_to_char(signatureS, temp, 32);
    // cout<<"w: "<<temp<<endl;
    mpz_init_set_str(gmp_temp, temp, 16);
    // element_set_str(W, temp, 16);
    element_set_mpz(W, gmp_temp);
    element_snprint(sss, 256, W);
    // cout<<sss<<endl;

    element_init_Zr(V, pairing);
    byte_to_char(v, temp, 32);
    // cout<<"v: "<<temp<<endl;
    mpz_init_set_str(gmp_temp, temp, 16);
    // element_set_str(V, temp, 16);
    element_set_mpz(V, gmp_temp);
    element_snprint(sss, 512, V);
    // cout<<sss<<endl;

    element_init_G1(t1, pairing);
    element_init_G1(t2, pairing);
    element_init_G1(U, pairing);

    // U' = [w]P1 - [v]Q
    element_pow_zn(t1, P1, W);
    element_pow_zn(t2, Q1, V);
    element_sub(U, t1, t2);

    // 生成hash值并比较
    element_snprint(sss, 256, P1);
    strcpy(temp, sss);
    element_snprint(sss, 256, Q1);
    strcat(temp, sss);
    element_snprint(sss, 256, U);
    // cout<<sss<<endl;
    strcat(temp, sss);
    strcat(temp, str0);
    // cout<<temp<<endl;
    SHA256((unsigned char*)temp, strlen(temp), bytes);
    byte_to_char(bytes, sss);
    // cout<<sss<<endl;

    element_clear(W);
    element_clear(V);
    element_clear(t2);
    element_clear(t1);
    element_clear(U);
    mpz_clear(gmp_temp);

    return memcmp(bytes, hash_res, 32);
}

/*
 * issuer生成证书ABCD
 */
void issuer_make_cred(pairing_t pairing, element_t P1, element_t Q1, element_t *A, element_t *B, element_t *C, element_t *D, element_t x, element_t y){
    element_t temp, r;

    element_init_Zr(r, pairing);
    element_init_Zr(temp, pairing);

    element_random(r);

    element_pow_zn(*A, P1, r);  // A = [r]P1

    element_pow_zn(*C, *A, x);
    element_mul(temp, r, x);
    element_mul(temp, temp, y);
    element_pow_zn(*B, Q1, temp);
    element_add(*C, *C, *B);  // C = [x]A + [rxy]Q
    element_mul(temp, r, y);
    element_pow_zn(*D, Q1, temp);  // D = [ry]Q

    element_pow_zn(*B, *A, y);  // B = [y]A


    element_clear(r);
    element_clear(temp);
}

/*
 * prover验证收到的证书是否有效
 */
int check_cred(pairing_t pairing, element_t P1, element_t P2, element_t A, element_t B, element_t C, element_t D, element_t X, element_t Y){
    element_t t1, t2, t3;
    
    element_init_GT(t1, pairing);
    element_init_GT(t2, pairing);
    element_init_G1(t3, pairing);

    // e(A, Y) =? e(B, P2)
    pairing_apply(t1, A, Y, pairing);
    pairing_apply(t2, B, P2, pairing);

    if(element_cmp(t1, t2)){
        cout<<"check cred fail";
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);

        return 0;
    }

    // e(A+D, X) =? e(C, P2)
    element_add(t3, A, D);
    pairing_apply(t1, t3, X, pairing);
    pairing_apply(t2, C, P2, pairing);

    if(element_cmp(t1, t2)){
        cout<<"check cred fail";
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);
        return 0;
    }
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);
    return 1;
}

/*
 * prover随机化证书
 */
void rand_cred(pairing_t pairing, element_t A, element_t B, element_t C, element_t D, element_t *R, element_t *S, element_t *T, element_t *W){
    element_t l;
    char sss[300];
    element_init_Zr(l, pairing);
    element_random(l);
    element_pow_zn(*R, A, l);
    element_pow_zn(*S, B, l);
    element_pow_zn(*T, C, l);
    element_pow_zn(*W, D, l);
}

/*
 * 将pbc的点格式转为TPM的点格式
 */
void element_to_ECCPoint(element_t e, TPM2B_ECC_POINT *P1){
    char sss[300], temp[300];
    mpz_t t;
    unsigned char bytes[32];
    element_snprint(sss, 256, e);
    // cout<<sss<<endl;
    int i=0;
    for(i=0;i<strlen(sss);i++){
        if(sss[i]==',') break;
    }
    // cout<<i<<endl;
    
    memcpy(temp, sss+1, i-1);
    temp[i-1] = '\0';
    // cout<<temp<<endl;
    mpz_init_set_str(t, temp, 10);
    mpz_get_str(temp, 16, t);
    // cout<<temp<<endl;
    char_to_byte(temp, bytes);
    memcpy(&P1->point.x.buffer, bytes, 32);

    memcpy(temp, sss+i+2, strlen(sss)-i-3);
    temp[strlen(sss)-i-3] = '\0';
    // cout<<temp<<endl;
    mpz_init_set_str(t, temp, 10);
    mpz_get_str(temp, 16, t);
    // cout<<temp<<endl;
    char_to_byte(temp, bytes);
    memcpy(&P1->point.y.buffer, bytes, 32);
}

/*
 * verifier验证证书
 */
int verify(pairing_t pairing, element_t R, element_t S, element_t T, element_t W, element_t X, element_t Y, element_t P2, unsigned char *signatureS, unsigned char *hash_res, unsigned char *signatureR, char *k){
    element_t t1, t2, t3;
    element_init_GT(t1, pairing);
    element_init_GT(t2, pairing);
    element_init_G1(t3, pairing);

    // e(R, Y) =? e(S, P2)
    pairing_apply(t1, R, Y, pairing);
    pairing_apply(t2, S, P2, pairing);
    if(element_cmp(t1, t2)){
        cout<<"check cred fail";
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);

        return 0;
    }
    // e(R+W, X) =? e(T, P2)
    element_add(t3, R, W);
    pairing_apply(t1, t3, X, pairing);
    pairing_apply(t2, T, P2, pairing);
    if(element_cmp(t1, t2)){
        cout<<"check cred fail";
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);

        return 0;
    }
    element_clear(t1);
    element_clear(t2);
    // element_clear(t3);

    unsigned char v[32];
    element_t sig, V, J2, L, E, K;
    SHA256_CTX h;
    mpz_t gmp_temp;

    SHA256_Init(&h);
    SHA256_Update(&h, signatureR, 32);
    SHA256_Update(&h, hash_res, 32);
    SHA256_Final(v, &h);

    char sss[300], str[2000];
    element_init_G1(J2, pairing);
    element_init_G1(K, pairing);
    element_init_G1(L, pairing);
    element_init_G1(E, pairing);
    element_init_Zr(sig, pairing);
    element_init_Zr(V, pairing);
    byte_to_char(signatureS, sss);
    
    mpz_init_set_str(gmp_temp, sss, 16);
    // element_set_str(sig, sss, 16);
    element_set_mpz(sig, gmp_temp);

    byte_to_char(v, sss);
    mpz_init_set_str(gmp_temp, sss, 16);
    // element_set_str(V, sss, 16);
    element_set_mpz(V, gmp_temp);
    element_set_str(K, k, 10);
    bsn_to_element(&J2);

    // L' = [s]J - [v]K
    element_pow_zn(L, J2, sig);
    element_pow_zn(t3, K, V);
    element_sub(L, L, t3);

    // E' = [s]S - [v]W
    element_pow_zn(E, S, sig);
    element_pow_zn(t3, W, V);
    element_sub(E, E, t3);

    element_snprint(sss, 256, R);
    strcpy(str, sss);
    element_snprint(sss, 256, S);
    strcat(str, sss);
    element_snprint(sss, 256, T);
    strcat(str, sss);
    element_snprint(sss, 256, W);
    strcat(str, sss);
    strcat(str, "2");

    // 相同的方式生成hash值并比较
    SHA256((unsigned char*)str, strlen(str), v);
    byte_to_char(v, sss);

    strcpy(str, sss);
    char msg[] = "1234567";
    strcat(str, msg);
    element_snprint(sss, 256, K);
    strcat(str, sss);
    // cout<<"K: "<<sss<<endl;
    element_snprint(sss, 256, L);
    strcat(str, sss);
    // cout<<"L: "<<sss<<endl;
    element_snprint(sss, 256, E);
    strcat(str, sss);
    // cout<<"E: "<<sss<<endl;
    strcat(str, J);
    strcat(str, "3");

    // cout<<str<<endl;
    element_clear(t3);
    element_clear(sig);
    element_clear(V);
    element_clear(J2);
    element_clear(L);
    element_clear(E);
    element_clear(K);
    mpz_clear(gmp_temp);

    SHA256((unsigned char*)str, strlen(str), v);
    return memcmp(v, hash_res, 32);


}

/*
 * 将字符串转为pbc格式的点
 */
void bsn_to_element(element_t *J2){
    char s[300], x[300], y[300];
    mpz_t temp;
    bsn_to_point(J, s, x, y);
    strcpy(s, "[");
    // cout<<x<<endl;
    mpz_init_set_str(temp, x, 16);
    mpz_get_str(x, 10, temp);
    strcat(s, x);
    strcat(s, ", ");
    // cout<<y<<endl;
    mpz_init_set_str(temp, y, 16);
    mpz_get_str(y, 10, temp);
    strcat(s, y);
    strcat(s, "]");
    // cout<<s<<endl;
    element_set_str(*J2, s, 10);
    // element_snprint(s, 256, *J2);
    // cout<<s<<endl;
    mpz_clear(temp);
}