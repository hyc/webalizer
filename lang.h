#ifndef _LANG_H
#define _LANG_H

extern char *language    ;
extern char *langcode    ;

extern char *msg_records ;
extern char *msg_addresses;
extern char *msg_ignored ;
extern char *msg_bad     ;
extern char *msg_in      ;
extern char *msg_seconds ;

extern char *msg_log_err ;
extern char *msg_log_use ;
extern char *msg_dir_err ;
extern char *msg_dir_use ;
extern char *msg_cur_dir ;
extern char *msg_hostname;
extern char *msg_ign_hist;
extern char *msg_no_hist ;
extern char *msg_get_hist;
extern char *msg_put_hist;
extern char *msg_hist_err;
extern char *msg_bad_hist;
extern char *msg_bad_conf;
extern char *msg_bad_key ;
extern char *msg_bad_date;
extern char *msg_ign_nscp;
extern char *msg_bad_rec ;
extern char *msg_no_vrec ;
extern char *msg_gen_rpt ;
extern char *msg_gen_sum ;
extern char *msg_get_data;
extern char *msg_put_data;
extern char *msg_no_data ;
extern char *msg_bad_data;
extern char *msg_data_err;
extern char *msg_dup_data;

extern char *msg_dns_nocf;
extern char *msg_dns_nodb;
extern char *msg_dns_nolk;
extern char *msg_dns_usec;
extern char *msg_dns_rslf;
extern char *msg_dns_none;
extern char *msg_dns_abrt;

extern char *msg_geo_open;
extern char *msg_geo_use ;
extern char *msg_geo_nolu;
extern char *msg_geo_dflt;

extern char *msg_nomem_ts;
extern char *msg_nomem_tr;
extern char *msg_nomem_tu;
extern char *msg_nomem_tc;
extern char *msg_nomem_ta;
extern char *msg_nomem_tsr;
extern char *msg_nomem_ti;
extern char *msg_nomem_dh;
extern char *msg_nomem_mh;
extern char *msg_nomem_u ;
extern char *msg_nomem_a ;
extern char *msg_nomem_r ;
extern char *msg_nomem_sc;
extern char *msg_nomem_i ;

extern char *msg_big_rec ;
extern char *msg_big_host;
extern char *msg_big_date;
extern char *msg_big_req ;
extern char *msg_big_ref ;
extern char *msg_big_user;
extern char *msg_big_one ;

extern char *msg_no_open ;

extern char *h_usage1    ;
extern char *h_usage2    ;
extern char *h_msg[];

/* HTML Strings */

extern char *msg_hhdr_sp ;
extern char *msg_hhdr_gt ;

extern char *msg_main_us ;
extern char *msg_main_per;
extern char *msg_main_sum;
extern char *msg_main_da ;
extern char *msg_main_mt ;

extern char *msg_hmth_du ;
extern char *msg_hmth_hu ;

extern char *msg_h_by    ;
extern char *msg_h_avg   ;
extern char *msg_h_max   ;
extern char *msg_h_total ;
extern char *msg_h_totals;
extern char *msg_h_day   ;
extern char *msg_h_mth   ;
extern char *msg_h_hour  ;
extern char *msg_h_hits  ;
extern char *msg_h_pages ;
extern char *msg_h_visits;
extern char *msg_h_files ;
extern char *msg_h_sites ;
extern char *msg_h_xfer  ;
extern char *msg_h_hname ;
extern char *msg_h_url   ;
extern char *msg_h_agent ;
extern char *msg_h_ref   ;
extern char *msg_h_ctry  ;
extern char *msg_h_search;
extern char *msg_h_uname ;

extern char *msg_hlnk_ds ;
extern char *msg_hlnk_hs ;
extern char *msg_hlnk_u  ;
extern char *msg_hlnk_s  ;
extern char *msg_hlnk_a  ;
extern char *msg_hlnk_c  ;
extern char *msg_hlnk_r  ;
extern char *msg_hlnk_en ;
extern char *msg_hlnk_ex ;
extern char *msg_hlnk_sr ;
extern char *msg_hlnk_i  ;

extern char *msg_mtot_ms ;
extern char *msg_mtot_th ;
extern char *msg_mtot_tf ;
extern char *msg_mtot_tx ;
extern char *msg_mtot_us ;
extern char *msg_mtot_ur ;
extern char *msg_mtot_ua ;
extern char *msg_mtot_uu ;
extern char *msg_mtot_ui ;
extern char *msg_mtot_mhd;
extern char *msg_mtot_mhh;
extern char *msg_mtot_mfd;
extern char *msg_mtot_mpd;
extern char *msg_mtot_msd;
extern char *msg_mtot_mvd;
extern char *msg_mtot_mkd;
extern char *msg_mtot_rc ;

extern char *msg_dtot_ds ;

extern char *msg_htot_hs ;

extern char *msg_ctry_use;

extern char *msg_top_top ;
extern char *msg_top_of  ;
extern char *msg_top_s   ;
extern char *msg_top_u   ;
extern char *msg_top_r   ;
extern char *msg_top_a   ;
extern char *msg_top_c   ;
extern char *msg_top_en  ;
extern char *msg_top_ex  ;
extern char *msg_top_sr  ;
extern char *msg_top_i   ;
extern char *msg_v_sites ;
extern char *msg_v_urls  ;
extern char *msg_v_refs  ;
extern char *msg_v_agents;
extern char *msg_v_search;
extern char *msg_v_users ;

extern char *msg_title   ;
extern char *msg_h_other ;

extern char *s_month[12];
extern char *l_month[12];

extern struct response_code response[];
extern struct country_code ctry[];

#endif  /* _LANG_H */
