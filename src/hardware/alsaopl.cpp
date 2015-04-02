/*
 *  Copyright (C) 2015   The DOSBox Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#include "config.h"
#include "inout.h"
#include "logging.h"

#include "uapi/sound/asound_fm.h"
#include <sys/ioctl.h>
#include <alsa/asoundlib.h>

// HACK (copied from opl3.h)
#define OPL3_LEFT 0
#define OPL3_RIGHT 0x100


snd_hwdep_t *_opl;
int _iface;


static void write_hwio(Bitu port,Bitu val,Bitu /*iolen*/) {
	static Bitu left_reg = 0;
	static Bitu right_reg = 0;
	LOG_MSG("write port %x",port);
	switch (port) {
	case 0x388:
		left_reg = val & 0xFF;
		break;
	case 0x38A:
		right_reg = val & 0xFF;
		break;

	case 0x389:
	{
		struct snd_dm_fm_command cmd;
		cmd.cmd = left_reg | OPL3_LEFT;
		cmd.val = val & 0xFF;
		snd_hwdep_ioctl(_opl, SNDRV_DM_FM_IOCTL_COMMAND, &cmd);
		break;
	}
	case 0x38B:
	{
		struct snd_dm_fm_command cmd;
		cmd.cmd = right_reg | OPL3_RIGHT;
		cmd.val = val & 0xFF;
		snd_hwdep_ioctl(_opl, SNDRV_DM_FM_IOCTL_COMMAND, &cmd);
		break;
	}
	default:
		break;
	}
}

static Bitu read_hwio(Bitu port,Bitu /*iolen*/) {
	LOG_MSG("read port %x",port);
	switch (port) {
	case 0x389:
	case 0x38B:
		return 0;

	case 0x388:
	{
		unsigned char info = 0; // left
		snd_hwdep_ioctl(_opl, SNDRV_DM_FM_IOCTL_READ_STATUS, &info);
		return info;
	}
	case 0x38A:
	{
		unsigned char info = 1; // right
		snd_hwdep_ioctl(_opl, SNDRV_DM_FM_IOCTL_READ_STATUS, &info);
		return info;
	}
	default:
		return 0;
	}
		
}

bool hwopl_dirty=false;

static IO_ReadHandleObject* hwOPL_ReadHandler[10] ;
static IO_WriteHandleObject* hwOPL_WriteHandler[10];

const Bit16u oplports[]={
		0x388,0x389,0x38A,0x38B};

static void reset()
{
	snd_hwdep_ioctl(_opl, SNDRV_DM_FM_IOCTL_RESET, 0);
	if (_iface != SND_HWDEP_IFACE_OPL2)
		snd_hwdep_ioctl(_opl, SNDRV_DM_FM_IOCTL_SET_MODE, (void *)SNDRV_DM_FM_MODE_OPL3);
	//clear();
}

static int init()
{
	int card = -1;
	snd_ctl_t *ctl;
	snd_hwdep_info_t *info;
	snd_hwdep_info_alloca(&info);

	int iface = SND_HWDEP_IFACE_OPL3;
//	if (_type == Config::kOpl2)
		iface = SND_HWDEP_IFACE_OPL2;

	// Look for OPL hwdep interface
	while (!snd_card_next(&card) && card >= 0) {
		int dev = -1;
		char name[100];
		sprintf(name, "hw:%d", card);

		if (snd_ctl_open(&ctl, name, 0) < 0)
			continue;

		while (!snd_ctl_hwdep_next_device(ctl, &dev) && dev >= 0) {
			sprintf(name, "hw:%d,%d", card, dev);

			if (snd_hwdep_open(&_opl, name, SND_HWDEP_OPEN_WRITE) < 0) 
				continue;

			printf("Trying %s\n", name);

			if (!snd_hwdep_info(_opl, info)) {
				int found = snd_hwdep_info_get_iface(info);
printf("Found: %d\n", found);
				// OPL3 can be used for (Dual) OPL2 mode
				if (found == iface || found == SND_HWDEP_IFACE_OPL3) {
printf("Found\n");
					snd_ctl_close(ctl);
					_iface = found;
					reset();
					return 0;
				}
			}

			// Wrong interface, try next device
			snd_hwdep_close(_opl);
			_opl = 0;
		}

		snd_ctl_close(ctl);
	}

	return -1;
}



void ALSAOPL_Init(Bitu /*blasteraddr*/)
{
	//LOG_MSG("hoplinit");
	if(init() != 0)
	{
		LOG_MSG("OPL passthrough: ALSA FM Direct device not found");
		return;
	}


	hwopl_dirty=true;

	// map the port
	LOG_MSG("Port mappings hardware -> DOSBox:");
	for(int i = 0; i < 4; i++)
	{
		hwOPL_ReadHandler[i]=new IO_ReadHandleObject();
		hwOPL_WriteHandler[i]=new IO_WriteHandleObject();
		Bit16u port=oplports[i];
		hwOPL_ReadHandler[i]->Install(port,read_hwio,IO_MB);
		hwOPL_WriteHandler[i]->Install(port,write_hwio,IO_MB);
	}
}

void ALSAOPL_Cleanup()
{
	if(hwopl_dirty) {
		for(int i = 0; i < 4; i++) {
			delete hwOPL_ReadHandler[i];
			delete hwOPL_WriteHandler[i];
		}
		hwopl_dirty=false;
	}

}
