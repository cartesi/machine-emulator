#!/bin/bash

# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

if [ -z "$GID" -o -z "$UID" -o -z "$USER" -o -z "$GROUP" ]; then
    echo Running as $(whoami)
    exec "$@"
else
  if [ ! $(getent group $GID) ]; then
    if [ $(getent group $GROUP) ]; then
      echo Group name $GROUP already exists
      GROUP=container-group-$GID
    fi
    groupadd -g $GID $GROUP
  else
    echo The id $GID of group $GROUP already exists
  fi
  if [ ! $(getent passwd $UID) ]; then
    if [ $(getent passwd $USER) ]; then
      echo User name $USER already exists.
      USER=container-user-$UID
    fi
    useradd -u $UID -g $GID -G $GROUP $USER
  else
    echo The id $UID of user $USER already exists
  fi
  USERNAME=$(id -nu $UID)
  export HOME=/home/$USERNAME
  mkdir -p $HOME
  chown $UID:$GID $HOME

# Workaround for issue with su-exec tty ownership
# Should be removed once ticket https://github.com/ncopa/su-exec/issues/33
# is resolved, or alternative solution with reusing file descriptors is found
# Test if stdin is associated with a terminal
  if [ -t 0 ]; then
    chown $UID:$GID $(/usr/bin/tty)
  fi

  echo Running as $USERNAME and group $(id -ng $UID)
  exec /usr/local/bin/su-exec $USERNAME "$@"
fi
