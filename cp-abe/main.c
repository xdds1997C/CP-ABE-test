#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <sys/time.h>
#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"


char* pub_file = "pub_key";
char*  msk_file = "master_key";
char** attrs    = 0;
char* priv_key_out_file = "priv_key";
char* in_file  = "a";
char* out_file = "a.cpabe";
char* dec_in_file="a.cpabe";
char* dec_out_file="a";
int   keep     = 1;

char* policy = 0;

//setup
int setup( )
{
	bswabe_pub_t* pub;
	bswabe_msk_t* msk;

	

	bswabe_setup(&pub, &msk);
	spit_file(pub_file, bswabe_pub_serialize(pub), 1);
	spit_file(msk_file, bswabe_msk_serialize(msk), 1);

	return 0;
}

//keygen
gint
comp_string( gconstpointer a, gconstpointer b)
{
	return strcmp(a, b);
}

//合并字符常量
char *join(char *src, char *dst) {
	char *c = (char *) malloc(strlen(src) + strlen(dst) + 1); 
	if (c == NULL) exit (1);
	char *tempc = c; 
	while (*src != '\0') {
		*c++ = *src++;
	}
	while ((*c++ = *dst++) != '\0') {
		;
	}
	
	return tempc;
}

//写入excel
void writeExcel(int num[],double time[],int len,char* dir)
{
	int i ;
	FILE *fp = NULL ;
	fp = fopen(dir,"w") ;
	for (i=0 ; i<len;i++)
		fprintf(fp,"%d\t%f\n",num[i],time[i] ) ;
	fclose(fp);
}

//获取文件大小
double get_f_size(char* f_name)
{
    FILE *file=fopen(f_name,"r");
    if(!file) return -1;
    fseek(file,0L,SEEK_END);
    int size=ftell(file);
    fclose(file);
    
    return (double)size;
}

//keygen参数设置
void keygen_parse_args(char* att,int num)
{
	
	
	GSList* alist;
	GSList* ap;
	
	alist = 0;

	int i;
	char *a="";
	for(i=0;i<num;i++){

		
		a=join(a,"lzlzl");
		int n;
		parse_attribute(&alist, a);
		alist = g_slist_sort(alist, comp_string);
		n = g_slist_length(alist);

		attrs = malloc((n + 1) * sizeof(char*));

		int j = 0;
		for( ap = alist; ap; ap = ap->next )
			attrs[j++] = ap->data;
		attrs[j] = 0;
	}

	
	
}
//私钥生成
double keygen( char* att ,int num)
{
	
	
	double keygen_time=0;

	
	struct timeval t_start,t_end;
	gettimeofday(&t_start,NULL);
	
	bswabe_pub_t* pub;
	bswabe_msk_t* msk;
	bswabe_prv_t* prv;

	keygen_parse_args(att,num);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	msk = bswabe_msk_unserialize(pub, suck_file(msk_file), 1);

	prv = bswabe_keygen(pub, msk, attrs);
	spit_file(priv_key_out_file, bswabe_prv_serialize(prv), 1);
	gettimeofday(&t_end,NULL);
	keygen_time=((double)(t_end.tv_sec*1000 + t_end.tv_usec/1000)-(double)(t_start.tv_sec*1000 + t_start.tv_usec/1000))/1000;

	return keygen_time;
}

//加密参数设置
void enc_parse_args(char* att,int num)
{
	int i;
	char b[1000]={"lzlzl"};
	for(i=0;i<num;i++){
		
        
		strcat(b," and lzlzl");
		
		
		
	}
	
	policy = parse_policy_lang(b);
		

	if( !policy )
		policy = parse_policy_lang(suck_stdin());

}

//加密
double enc( char* att,int num)
{
	double enc_time;
	struct timeval t_start,t_end;
	gettimeofday(&t_start,NULL);

	bswabe_pub_t* pub;
	bswabe_cph_t* cph;
	int file_len;
	GByteArray* plt;
	GByteArray* cph_buf;
	GByteArray* aes_buf;
	element_t m;

	enc_parse_args(att,num);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

  if( !(cph = bswabe_enc(pub, m, policy)) )
		die("%s", bswabe_error());
	free(policy);

	cph_buf = bswabe_cph_serialize(cph);
	bswabe_cph_free(cph);

	plt = suck_file(in_file);
	file_len = plt->len;
	aes_buf = aes_128_cbc_encrypt(plt, m);
	g_byte_array_free(plt, 1);
	element_clear(m);

	write_cpabe_file(out_file, cph_buf, file_len, aes_buf);

	g_byte_array_free(cph_buf, 1);
	g_byte_array_free(aes_buf, 1);

	if( !keep )
		unlink(in_file);
	gettimeofday(&t_end,NULL);
	enc_time=((double)(t_end.tv_sec*1000 + t_end.tv_usec/1000)-(double)(t_start.tv_sec*1000 + t_start.tv_usec/1000))/1000;
	return enc_time;
}

//解密
double dec( )
{

	double dec_time;
	struct timeval t_start,t_end;
	gettimeofday(&t_start,NULL);

	bswabe_pub_t* pub;
	bswabe_prv_t* prv;
	int file_len;
	GByteArray* aes_buf;
	GByteArray* plt;
	GByteArray* cph_buf;
	bswabe_cph_t* cph;
	element_t m;

	

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	prv = bswabe_prv_unserialize(pub, suck_file(priv_key_out_file), 1);

	read_cpabe_file(dec_in_file, &cph_buf, &file_len, &aes_buf);

	cph = bswabe_cph_unserialize(pub, cph_buf, 1);
	if( !bswabe_dec(pub, prv, cph, m) )
		die("%s", bswabe_error());
	bswabe_cph_free(cph);

	plt = aes_128_cbc_decrypt(aes_buf, m);
	g_byte_array_set_size(plt, file_len);
	g_byte_array_free(aes_buf, 1);

	spit_file(dec_out_file, plt, 1);

	if( !keep )
		unlink(in_file);

	gettimeofday(&t_end,NULL);
	dec_time=((double)(t_end.tv_sec*1000 + t_end.tv_usec/1000)-(double)(t_start.tv_sec*1000 + t_start.tv_usec/1000))/1000;
	return dec_time;
}


int main(int argc, char** argv){
	
    char* att="";

	int i;
	int num=0;

	int nums[200];
	double keygen_times[200];
	double enc_times[200];
	double dec_times[200];

	double pub_size[200];
	double priv_size[200];
    double ct_size[200];

	for(i=0;i<50;i++){
		setup();
		pub_size[i]=get_f_size("pub_key");

		num++;
		nums[i]=num;

	    double keygen_time;
		keygen_time=keygen(att,num);
		priv_size[i]=get_f_size("priv_key");
		keygen_times[i]=keygen_time;
		
		
		double enc_time;
		enc_time=enc(att,num);
		ct_size[i]=get_f_size("a.cpabe");
		enc_times[i]=enc_time;
		
		double dec_time;
		dec_time=dec();
		dec_times[i]=dec_time;

		
	}
	writeExcel(nums,keygen_times,num-1,"./data/cpabe-keygen.xls");
	writeExcel(nums,enc_times,num-1,"./data/cpabe-enc.xls");
	writeExcel(nums,dec_times,num-1,"./data/cpabe-dec.xls");
	writeExcel(nums,pub_size,num-1,"./data/pub_key.xls");
	writeExcel(nums,priv_size,num-1,"./data/priv_key.xls");
	writeExcel(nums,ct_size,num-1,"./data/ct.xls");

	return 0;

}