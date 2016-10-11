/**
 * @file fp2.c
 * @author Mike Scott
 * @author Kealan McCusker
 * @date 19th May 2015
 * @brief AMCL Fp^2 functions
 * @note FP2 elements are of the form a+ib, where i is sqrt(-1)
 *
 * LICENSE
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/* AMCL Fp^2 functions */
/* SU=m, m is Stack Usage (no lazy )*/

#include "amcl.h"

/* SU= 8, Tests for FP2 equal to zero */
int FP2_iszilch(FP2 *x)
{
    FP2_reduce(x);
    if (BIG_iszilch(x->a) && BIG_iszilch(x->b)) return 1;
    return 0;
}

/* Conditionally copies second FP2 parameter to the first (without branching) */
void FP2_cmove(FP2 *f,FP2 *g,int d)
{
    BIG_cmove(f->a,g->a,d);
    BIG_cmove(f->b,g->b,d);
}

/* SU= 48, Tests for FP2 equal to one */
int FP2_isunity(FP2 *x)
{
    BIG one;
    FP_one(one);
    FP2_reduce(x);
    if (BIG_comp(x->a,one)==0 && BIG_iszilch(x->b)) return 1;
    return 0;
}

/* SU= 8, Reduces all components of possibly unreduced FP2 mod Modulus */
void FP2_reduce(FP2 *w)
{
    FP_reduce(w->a);
    FP_reduce(w->b);
}

/* SU= 16, Tests for equality of two FP2s */
int FP2_equals(FP2 *x,FP2 *y)
{
    FP2_reduce(x);
    FP2_reduce(y);
    if (BIG_comp(x->a,y->a)==0 && BIG_comp(x->b,y->b)==0)
        return 1;
    return 0;
}

/* SU= 16, Initialise FP2 from two BIGs in n-residue form */
void FP2_from_FPs(FP2 *w,BIG x,BIG y)
{
    BIG_copy(w->a,x);
    BIG_copy(w->b,y);
}

/* SU= 16, Initialise FP2 from two BIG integers */
void FP2_from_BIGs(FP2 *w,BIG x,BIG y)
{
    BIG_copy(w->a,x);
    BIG_copy(w->b,y);
    FP_nres(w->a);
    FP_nres(w->b);
}

/* SU= 8, Initialise FP2 from single BIG in n-residue form */
void FP2_from_FP(FP2 *w,BIG x)
{
    BIG_copy(w->a,x);
    BIG_zero(w->b);
}

/* SU= 8, Initialise FP2 from single BIG */
void FP2_from_BIG(FP2 *w,BIG x)
{
    BIG_copy(w->a,x);
    FP_nres(w->a);
    BIG_zero(w->b);
}

/* SU= 16, Copy FP2 to another FP2 */
void FP2_copy(FP2 *w,FP2 *x)
{
    if (w==x) return;
    BIG_copy(w->a,x->a);
    BIG_copy(w->b,x->b);
}

/* SU= 8, Set FP2 to zero */
void FP2_zero(FP2 *w)
{
    BIG_zero(w->a);
    BIG_zero(w->b);
}

/* SU= 48, Set FP2 to unity */
void FP2_one(FP2 *w)
{
    BIG one;
    FP_one(one);
    FP2_from_FP(w,one);
}

/* SU= 88, Negation of FP2 */
void FP2_neg(FP2 *w,FP2 *x)
{
    /* Just one neg! */
    BIG m,t;
    FP2_norm(x);
    FP_add(m,x->a,x->b);
    FP_neg(m,m);
    BIG_norm(m);
    FP_add(t,m,x->b);
    FP_add(w->b,m,x->a);
    BIG_copy(w->a,t);
}

/* SU= 16, Conjugation of FP2 */
void FP2_conj(FP2 *w,FP2 *x)
{
    BIG_copy(w->a,x->a);
    FP_neg(w->b,x->b);
}

/* SU= 16, Addition of two FP2s */
void FP2_add(FP2 *w,FP2 *x,FP2 *y)
{
    FP_add(w->a,x->a,y->a);
    FP_add(w->b,x->b,y->b);
}

/* SU= 16, Subtraction of two FP2s */
void FP2_sub(FP2 *w,FP2 *x,FP2 *y)
{
    FP2 m;
    FP2_neg(&m,y);
    FP2_add(w,x,&m);
}

/* SU= 16, Multiplication of an FP2 by an n-residue */
void FP2_pmul(FP2 *w,FP2 *x,BIG s)
{
    FP_mul(w->a,x->a,s);
    FP_mul(w->b,x->b,s);
}

/* SU= 16, Multiplication of an FP2 by a small integer */
void FP2_imul(FP2 *w,FP2 *x,int s)
{
    FP_imul(w->a,x->a,s);
    FP_imul(w->b,x->b,s);
}

/* SU= 128, Squaring an FP2 */
void FP2_sqr(FP2 *w,FP2 *x)
{
    BIG w1,w3,mb;

    FP_mul(w3,x->a,x->b); /* norms x */
    FP_add(w1,x->a,x->b); /* w1#2 w1=2 */
    FP_neg(mb,x->b);      /* mb#2 mb=1 */
    FP_add(w->a,x->a,mb);   /* w2#3 w2=3 */
    FP_mul(w->a,w1,w->a);     /* w->a#2 w->a=1 w1&w2=6 w1*w2=2 */

    FP_add(w->b,w3,w3); /* w->b#4 w->b=2 */

    FP2_norm(w);

}

/* SU= 168, Multiplication of two FP2s */
void FP2_mul(FP2 *w,FP2 *x,FP2 *y)
{
    BIG w1,w2,w5,mw;

    FP_mul(w1,x->a,y->a);  /* norms x  */
    FP_mul(w2,x->b,y->b);  /* and y */

    FP_add(w5,x->a,x->b);

    FP_add(w->b,y->a,y->b);

    FP_mul(w->b,w->b,w5);
    FP_add(mw,w1,w2);
    FP_neg(mw,mw);

    FP_add(w->b,w->b,mw);
    FP_add(mw,w1,mw);
    FP_add(w->a,w1,mw);

    FP2_norm(w);

}

/* SU= 16, Formats and outputs as [a,b] an FP2 to the console */
void FP2_output(FP2 *w)
{
    FP2_reduce(w);
    FP_redc(w->a);
    FP_redc(w->b);
    printf("[");
    BIG_output(w->a);
    printf(",");
    BIG_output(w->b);
    printf("]");
    FP_nres(w->a);
    FP_nres(w->b);
}

/* SU= 8, Formats and outputs as [a,b] an FP2 to the console in raw form (for debugging) */
void FP2_rawoutput(FP2 *w)
{
    printf("[");
    BIG_rawoutput(w->a);
    printf(",");
    BIG_rawoutput(w->b);
    printf("]");
}

/* SU= 128, Inverting an FP2 */
void FP2_inv(FP2 *w,FP2 *x)
{
    BIG m,w1,w2;
    BIG_rcopy(m,Modulus);
    FP2_norm(x);
    FP_sqr(w1,x->a);
    FP_sqr(w2,x->b);
    FP_add(w1,w1,w2);

    FP_redc(w1);
    BIG_invmodp(w1,w1,m);
    FP_nres(w1);
    FP_mul(w->a,x->a,w1);
    FP_neg(w1,w1);
    FP_mul(w->b,x->b,w1);
//	FP2_norm(w);
}

/* SU= 16, Divide an FP2 by 2 */
void FP2_div2(FP2 *w,FP2 *x)
{
    FP_div2(w->a,x->a);
    FP_div2(w->b,x->b);
}

/* SU= 128, Multiply an FP2 by (1+sqrt(-1)) */
void FP2_mul_ip(FP2 *w)
{
    FP2 t;
    BIG z;

    FP2_norm(w);
    FP2_copy(&t,w);

    BIG_copy(z,w->a);
    FP_neg(w->a,w->b);
    BIG_copy(w->b,z);

    FP2_add(w,&t,w);
    FP2_norm(w);
}

/* SU= 88, Divide an FP2 by (1+sqrt(-1)) */
void FP2_div_ip(FP2 *w)
{
    FP2 t;
    FP2_norm(w);
    FP_add(t.a,w->a,w->b);
    FP_sub(t.b,w->b,w->a);
    FP2_div2(w,&t);
}

/* SU= 8, Normalises the components of an FP2 */
void FP2_norm(FP2 *w)
{
    BIG_norm(w->a);
    BIG_norm(w->b);
}

/* SU= 208, Raises an FP2 to the power of a BIG */
void FP2_pow(FP2 *r,FP2* a,BIG b)
{
    FP2 w;
    BIG z,one,zilch;
    int bt;

    BIG_norm(b);
    BIG_copy(z,b);
    FP2_copy(&w,a);
    FP_one(one);
    BIG_zero(zilch);
    FP2_from_FP(r,one);
    while(1)
    {
        bt=BIG_parity(z);
        BIG_shr(z,1);
        if (bt) FP2_mul(r,r,&w);
        if (BIG_comp(z,zilch)==0) break;
        FP2_sqr(&w,&w);
    }
    FP2_reduce(r);
}

/* sqrt(a+ib) = sqrt(a+sqrt(a*a-n*b*b)/2)+ib/(2*sqrt(a+sqrt(a*a-n*b*b)/2)) */
/* Square root of an FP2 */
int FP2_sqrt(FP2 *w,FP2 *u)
{
    BIG w1,w2,q;
    FP2_copy(w,u);
    if (FP2_iszilch(w)) return 1;

    BIG_rcopy(q,Modulus);
    FP_sqr(w1,w->b);
    FP_sqr(w2,w->a);
    FP_add(w1,w1,w2);
    if (!FP_qr(w1))
    {
        FP2_zero(w);
        return 0;
    }
    FP_sqrt(w1,w1);
    FP_add(w2,w->a,w1);
    FP_div2(w2,w2);
    if (!FP_qr(w2))
    {
        FP_sub(w2,w->a,w1);
        FP_div2(w2,w2);
        if (!FP_qr(w2))
        {
            FP2_zero(w);
            return 0;
        }
    }
    FP_sqrt(w2,w2);
    BIG_copy(w->a,w2);
    FP_add(w2,w2,w2);
    FP_redc(w2);
    BIG_invmodp(w2,w2,q);
    FP_nres(w2);
    FP_mul(w->b,w->b,w2);
    return 1;
}

/*
int main()
{
	int i;
	FP2 w,z;
	BIG a,b,e;
	BIG pp1,pm1;
	BIG_unity(a); BIG_unity(b);
	FP2_from_BIGs(&w,a,b);
//	for (i=0;i<100;i++)
//	{
//		BIG_randomnum(a); BIG_randomnum(b);
//		BIG_mod(a,Modulus); BIG_mod(b,Modulus);
//		FP2_from_FPs(&w,a,b);
//		FP2_output(&w);
//		FP2_inv(&z,&w);
//				FP2_output(&z);
//		FP2_inv(&z,&z);
//				FP2_output(&z);
//				FP2_output(&w);
//		if (FP2_comp(&w,&z)!=1) printf("error \n");
//		else printf("OK \n");
//	}
//exit(0);
	printf("w= "); FP2_output(&w); printf("\n");
	BIG_zero(e); BIG_inc(e,27);
	FP2_pow(&w,&w,e);
	FP2_output(&w);
exit(0);
	BIG_rcopy(pp1,Modulus);
	BIG_rcopy(pm1,Modulus);
	BIG_inc(pp1,1);
	BIG_dec(pm1,1);
	BIG_norm(pp1);
	BIG_norm(pm1);
	FP2_pow(&w,&w,pp1);
	FP2_pow(&w,&w,pm1);
	FP2_output(&w);
}

*/
