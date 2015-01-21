#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "common-utils.h"
#include "cli1-xdr.h"
#include "xdr-generic.h"
#include "glusterd.h"
#include "glusterd-op-sm.h"
#include "glusterd-store.h"
#include "glusterd-utils.h"
#include "glusterd-volgen.h"
#include "run.h"
#include "syscall.h"
#include "byte-order.h"
#include "compat-errno.h"

#include <sys/wait.h>
#include <dlfcn.h>

#define GANESHA_HA_CONF  "/etc/ganesha/ganesha-ha.conf"

struct ganesha_host {
	char *host;
	struct list_head list_host;
};

int get_host_from_haconfig(glusterd_volinfo_t *volinfo, dict_t *dict);

int check_dbus_config()
{
return 1;
}

int is_ganesha_host ( )
{
	char *host_from_file = NULL;
	glusterd_conf_t *priv = NULL;
	glusterd_volinfo_t *volinfo = NULL;
	glusterd_brickinfo_t *brickinfo = NULL;
	char *hostname = NULL;
	FILE *fp;
	char buf[40];
	int ret = 0;


        priv =  THIS->private;
        GF_ASSERT(priv);
	
	fp = fopen (GANESHA_HA_CONF,"r");

        if ( fp == NULL)
        {
                gf_log ( "",GF_LOG_INFO,"couldn't open the file");
                return 1;
        }

	list_for_each_entry(volinfo,&priv->volumes, vol_list) {
		        list_for_each_entry (brickinfo, &volinfo->bricks, brick_list) {
			hostname = brickinfo->hostname;
	gf_log ("",GF_LOG_INFO,"the hostname is %s", hostname);
	}
	break;
	}


	host_from_file = fgets ( buf, 30, fp );
	gf_log("",GF_LOG_INFO, "the host_from_file is %s", host_from_file);
	ret = gf_strip_whitespace (buf, strlen (buf));
        if (ret == -1)
              goto out;
	
	
	if ( strcmp ( hostname, host_from_file) == 0) {

	gf_log ("", GF_LOG_DEBUG, "One of NFS-Ganesha hosts found");
	return 1;
	
	}
	
out : 	return ret ;
}	
	
	
int create_export_config (char *volname, char **op_errstr)
{
	runner_t                runner                     = {0,};
	int ret = -1;
	runinit (&runner);
	
	gf_log("",GF_LOG_INFO,"running create_EXPORT");
	runner_add_args (&runner, "sh", "/etc/ganesha/create_export.sh", volname, NULL);
	ret = runner_run(&runner);

	if ( ret == -1 ) {
	
	gf_asprintf ( op_errstr, "Failed to create NFS-Ganesha export config file.");
	return ret;
	
	}

	return 1;
}

int  ganesha_manage_export (dict_t *dict, char *value, char **op_errstr)
{
	runner_t runner = {0,};
	int ret = -1;
	runinit (&runner);
	FILE *fp;
	char buf[40];
	glusterd_volinfo_t *volinfo = NULL;
	char *volname = NULL;
	glusterd_brickinfo_t *brickinfo = NULL;
	
      	ret = dict_get_str (dict, "volname", &volname);
        if (ret) {
        	gf_log ("", GF_LOG_ERROR, "Unable to get volume name");
        	goto out;
        }
        
        ret = glusterd_volinfo_find (volname, &volinfo);
        if (ret) {
                gf_log ("", GF_LOG_ERROR, FMTSTR_CHECK_VOL_EXISTS,
                        volname);
                goto out;
        }
	
	fp = fopen (GANESHA_HA_CONF,"r");

	if ( fp == NULL)
	{
        	gf_log ( "",GF_LOG_INFO,"couldn't open the file");
        	return 1;
	}

	//Read the hostname of the current node
	list_for_each_entry (brickinfo, &volinfo->bricks, brick_list)
        {
                gf_log("",GF_LOG_INFO,"the hostname is %s", brickinfo->hostname);
                if (!uuid_compare( brickinfo->uuid,MY_UUID)) {
                	gf_log("",GF_LOG_INFO, "it is the local node");
                // Reading GANESHA_HA_CONF to get the host names listed
        	while ( fgets ( buf, 30, fp ) != NULL)
        	{

        		gf_log("",GF_LOG_INFO, "the value is %s", buf);
        		//key = ( void *) buf;
        		//list = &key;
        		//list_add_tail(&hlist->list_host,list);
        		ret = gf_strip_whitespace (buf, strlen (buf));
        		if (ret == -1)
             			goto out;
        		if (strcmp( buf, brickinfo->hostname) == 0){
				if ( strcmp (value,"on") == 0)
				create_export_config(volname, op_errstr);
        		gf_log("",GF_LOG_INFO,"runing dbus send");
			gf_log("",GF_LOG_INFO," the value on/off is %s", value);
        		
			runner_add_args (&runner, "sh", "/etc/ganesha/dbus-send.sh", value, volname ,NULL);
        		ret = runner_run(&runner);
			
			gf_log("", GF_LOG_INFO," the return value is %d ", ret);
        //return ret;
			gf_log("",GF_LOG_INFO,"the host is %s", buf);
        }

 
	}
		fclose(fp);
		break;
        }
}

if ( ret == -1)

gf_asprintf(op_errstr, "Dynamic export addition/deletion failed. Please see log file for details");

out:return ret;
}

int tear_down_cluster()
{
	int ret = -1;
	runner_t runner = {0,};
	if (is_ganesha_host())
	{
	
	gf_log ( "",GF_LOG_INFO,"before teardown");
	runinit (&runner);
	
	runner_add_args (&runner, "sh","/etc/ganesha/ganesha-ha.sh","teardown",NULL);
	ret = runner_run(&runner);
	}

	return ret;
}

int setup_cluster()
{
	int ret = 1;
	runner_t runner = {0,};
	if (is_ganesha_host())
	{
        gf_log ("",GF_LOG_INFO, "I am a ganesha host");
        runinit (&runner);
        runner_add_args (&runner, "sh","/etc/ganesha/ganesha-ha.sh","setup",NULL);

	ret =  runner_run(&runner);
	
	}
return ret;
}


int stop_ganesha(char **op_errstr)
{
	runner_t                runner                     = {0,};
	int ret = 1;
	
	//ret = tear_down_cluster();
	if ( ret == -1 ){
	gf_asprintf ( op_errstr, "Cleanup of NFS-Ganesha HA config failed.");
	goto out;
	}
	
	runinit (&runner);
	runner_add_args (&runner, "pkill", "ganesha.nfsd",NULL);
	ret = runner_run(&runner);
	
	if ( ret == -1)
	gf_asprintf ( op_errstr, "NFS-Ganesha could not be stopped. ");
out:    
	return ret;
}

int start_ganesha(dict_t *dict, char ** op_errstr)
{

	runner_t                runner                     = {0,};
	int ret = -1;
	char key[1024] = {0,};
	char *hostname = NULL;
	long int i =1;
	dict_t *vol_opts =  NULL;
	glusterd_volinfo_t *volinfo1 = NULL;
	int count =0;
	dict_t *dict1 = NULL;
	char *volname =  NULL;
	glusterd_conf_t *priv = NULL;

	priv =  THIS->private;
	GF_ASSERT(priv);

	dict1 = dict_new();
	if (!dict1)
        	goto out;
	
	list_for_each_entry(volinfo1,&priv->volumes, vol_list) {
                memset (key, 0, sizeof (key));
                snprintf (key, sizeof (key), "volume%d", count);
                ret = dict_set_str (dict1, key, volinfo1->volname);
                if (ret)
                        goto out;
                vol_opts = volinfo1->dict;
                ret = dict_set_str(vol_opts, "nfs.disable","on");
		//ret = dict_set_str(vol_opts, "features.ganesha","on");

                count++;

        }

	glusterd_nfs_server_stop();
	
	runinit(&runner);
	runner_add_args (&runner, "/usr/bin/ganesha.nfsd",
                         "-L", "/nfs-ganesha-op.log",
                         "-f","/etc/ganesha/nfs-ganesha.conf","-N", "NIV_FULL_DEBUG","-d", NULL);
	ret =  runner_run(&runner);
	if ( ret == -1 ){
	gf_asprintf (op_errstr, "NFS-Ganesha failed to start. Please see log file for details");
	goto out;
	}

	//ret = setup_cluster();
	if ( ret == -1 ){
	gf_asprintf (op_errstr, "Failed to set up HA config for NFS-Ganesha. Please check the log file for details");
	goto out;
	}

out : 
	return ret;
}


int32_t
glusterd_check_if_ganesha_trans_enabled (glusterd_volinfo_t *volinfo)
{
        int32_t  ret           = 0;
        int      flag          = _gf_false;

        flag = glusterd_volinfo_get_boolean (volinfo, "features.ganesha");
        if (flag == -1) {
                gf_log ("", GF_LOG_ERROR, "failed to ganesha status");
                ret = -1;
                goto out;
        }

        if (flag == _gf_false) {
                ret = -1;
                goto out;
       }
        ret = 0;
out:
        return ret;
}


int glusterd_handle_ganesha_op(dict_t *dict, char **op_errstr,char *key,char *value)
{

        int32_t                 ret          = -1;
        char                   *volname      = NULL;
        int                     type         = -1;
        xlator_t               *this         = NULL;
        static int             export_id    = 1;
	glusterd_volinfo_t     *volinfo      = NULL;
        char *option =  NULL;

        GF_ASSERT(dict);
        GF_ASSERT(op_errstr);
        
/*	ret = dict_get_str (dict, "volname", &volname);
                  if (ret) {
                    gf_log ("", GF_LOG_ERROR, "Unable to get volume name");
                             goto out;
                           }
	
	ret = glusterd_volinfo_find (volname, &volinfo);
        if (ret) {
                gf_log ("", GF_LOG_ERROR, FMTSTR_CHECK_VOL_EXISTS,
                        volname);
                goto out;
        }
*/	

        gf_log ( "",GF_LOG_INFO,"the value is %s ",value);
        if (strcmp (key, "ganesha.enable") == 0)
        {
   
                ret =  ganesha_manage_export(dict,value,op_errstr);

                        if ( ret < 0 )
                                goto out;
        }

      
        if ( strcmp (key, "features.ganesha") == 0)
        {
		
		if ( strcmp ( value, "on") == 0 )
		{
               		ret =  start_ganesha(dict, op_errstr);

                        if ( ret < 0 )
                                goto out;
 
        	}
	

		
		else if ( strcmp ( value, "off" ) == 0 )
		{
			ret = stop_ganesha ( op_errstr );
			
			if ( ret < 0 )
				goto out;

		}
}

out :

return ret;

}


