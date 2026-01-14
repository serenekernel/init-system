# init_system

The initial userspace process for the Serene.

## Overview

This is the first process started by the kernel. It is responsible for bootstrapping userspace and starting servers as well as ipc discovery.

## Features

- Creates and manages IPC endpoints
- Receives and processes messages from other processes
- Uses serenelib for system calls and debug output

## Building

Automatically built as part of serene-dist.
