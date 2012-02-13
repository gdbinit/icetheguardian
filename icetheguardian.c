/*
 * _________ _______  _______ 
 * \__   __/(  ____ \(  ____ \
 *    ) (   | (    \/| (    \/
 *    | |   | |      | (__    
 *    | |   | |      |  __)   
 *    | |   | |      | (      
 * ___) (___| (____/\| (____/\
 * \_______/(_______/(_______/
 *
 * _____ _           ___                  _ _           
 *|_   _| |_  ___   / __|_  _ __ _ _ _ __| (_)__ _ _ _  
 *  | | | ' \/ -_) | (_ | || / _` | '_/ _` | / _` | ' \ 
 *  |_| |_||_\___|  \___|\_,_\__,_|_| \__,_|_\__,_|_||_|
 *
 * v0.1
 *
 * (c) 2011, fG! - reverser@put.as - http://reverse.put.as
 *
 * -> You are free to use this code as long as you maintain the original copyright <-
 *
 * A PoC to protect critical OS X files using TrustedBSD Mac framework.
 *
 * MAC_POLICY_SET should be used instead of directly configuring the
 * kernel entry points. If this is used, duplicate symbol errors arise.
 * Most probably because I am using XCode's kernel extension template.
 *
 * Based on Sedarwin project sample policies code.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define VERSION "0.1"

#include <mach/mach_types.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <security/mac_policy.h>
#include <sys/proc.h>
#include <string.h>
#include <sys/systm.h>
#include <stdbool.h> 
#include <sys/param.h>
#include <stdint.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
//#include <sys/vnode_internal.h>

static void
mac_ice_policy_initbsd(struct mac_policy_conf *conf)
{
	// nothing to do here...
}

/*
 * install a hook at open() syscall
 * here we can intercept calls to files we want to protect and deny or allow access
 */
static int
mac_ice_policy_open(kauth_cred_t cred,
                    struct vnode *vp,
                    struct label *label,
                    int acc_mode)
{
    const char *vname = NULL;
	char *pbuf, cbuf[MAXCOMLEN+1];
	int clen, plen, error;
	int retvalue = 0;
	kern_return_t ret;
	
	// nothing to see
	if (vp == NULL) 
	{
		return (retvalue);
	}
	// not using yet the full path...
	/*
	MALLOC(pbuf, char *, MAXPATHLEN, M_TEMP, M_WAITOK);
	if (pbuf == NULL) 
	{
		return (retvalue);
	}
	plen = MAXPATHLEN;
	// get path retrieves the full path + target file
	error = vn_getpath(vp, pbuf, &plen);
	 */
	// this retrieves the target file
    vname = vnode_getname(vp);
	if (vname)
	{
		clen = sizeof(cbuf);
		// retrieve process name
        proc_selfname(cbuf, clen);
//		printf("proc name %s, pid %d, ppid %d, uid %d open %s\n", cbuf, proc_selfpid(), proc_selfppid(), cred->cr_uid, pbuf);
		// our target - /System/Library/LaunchDaemons/com.apple.xprotectupdater.plist
		if (strcasecmp(vname, "com.apple.xprotectupdater.plist") == 0)
		{
			// if it's not the correct process name
			// of course this can be spoofed so this needs better matching here
			if (strcasecmp(cbuf,"XProtectUpdater"))
			{
				// display an alert
				// this is deprecated and the correct way would be to pass this to an userland helper
				// just a PoC so this does the job for now
				ret = KUNCUserNotificationDisplayNotice(
														10,		// Timeout
														0,		// Flags
														NULL,	// iconpath
														NULL,	// soundpath
														NULL,	// localization path
														"Security Alert", // alert header
														"Some process is trying to access XProtect plist file!", // alert message
														"OK"	// button title
														);
				// and finally deny access to the file
				retvalue = EPERM;
			}
		}
		// cleaning
		vnode_putname(vname);
	}        
	// free buffers
    //FREE(pbuf, M_TEMP);
    return(retvalue);
}

// register our handles
static struct mac_policy_ops mac_ice_ops =
{
	.mpo_policy_initbsd	= mac_ice_policy_initbsd,
    .mpo_vnode_check_open = mac_ice_policy_open,
};

static mac_policy_handle_t mac_ice_handle;

static struct mac_policy_conf ice_mac_policy_conf = {      
	.mpc_name               = "ice_the_guardian",                      
	.mpc_fullname           = "Ice, The Guardian!",                   
	.mpc_labelnames         = NULL,                       
	.mpc_labelname_count    = 0,                       
	.mpc_ops                = &mac_ice_ops,                        
	.mpc_loadtime_flags     = MPC_LOADTIME_FLAG_UNLOADOK,     // modify this to 0 for "production" else this kernel module can be unloaded!
	.mpc_field_off          = NULL,                         
	.mpc_runtime_flags      = 0                        
};

// start the fun
kern_return_t icetheguardian_start (kmod_info_t * ki, void * d) {
	return mac_policy_register(&ice_mac_policy_conf,
							   &mac_ice_handle, d);
}

// stop the fun :-(
kern_return_t icetheguardian_stop (kmod_info_t * ki, void * d) {
	return mac_policy_unregister(mac_ice_handle);
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

