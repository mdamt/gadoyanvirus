# Mohammad DAMT [mdamt at bisnisweb dot com] 
# (c) 2004, PT Cakram Datalingga Duaribu
#    
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

AM_CFLAGS=$(CLAMAV_INCLUDE) $(gadoyanvirus_cflags) 

AUTOMAKE_OPTIONS = no-dependencies
bin_PROGRAMS=gadoyanvirus
gadoyanvirus_SOURCES=gadoyanvirus.c
gadoyanvirus_LDADD=$(CLAMAV_LIB) $(gadoyanvirus_ldflags)

install:
	strip gadoyanvirus
	mkdir -m 711 -p $(GADOYANVIRUS_DIR)/quarantine/tmp $(GADOYANVIRUS_DIR)/bin 
	chown $(SMTP_UID):$(SMTP_GID) $(GADOYANVIRUS_DIR) $(GADOYANVIRUS_DIR)/quarantine $(GADOYANVIRUS_DIR)/quarantine/tmp
	$(INSTALL) -m 755 gadoyanvirus $(GADOYANVIRUS_DIR)/bin
