/*
 * The SCSI sense key Additional Sense Code / Additional Sense Code Qualifier
 *
 * Copyright (C) 2007 Mark Harvey <markh794@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * SENSE keys
 */
#define NO_SENSE			0x00
#define	RECOVERED_ERROR			0x01
#define NOT_READY			0x02
#define MEDIUM_ERROR			0x03
#define	HARDWARE_ERROR			0x04
#define ILLEGAL_REQUEST			0x05
#define UNIT_ATTENTION			0x06
#define DATA_PROTECT			0x07
#define	BLANK_CHECK			0x08

/* Key 0: No Sense Errors */
#define NO_ADDITIONAL_SENSE			0x0000
#define ASC_MARK				0x0001
#define ASC_EOM					0x0002
#define ASC_BOM					0x0004
#define ASC_END_OF_DATA				0x0005
#define ASC_OP_IN_PROGRESS			0x0016
#define ASC_DRIVASC_REQUIRES_CLEANING		0x8282

/* Key 1: Recovered Errors */
#define ASC_WRITASC_ERROR			0x0c00
#define ASC_READ_ERROR				0x1100
#define ASC_RECOVERED_WITH_RETRYS		0x1701
#define ASC_MEDIA_LOAD_EJECT_ERROR		0x5300
#define ASC_FAILURASC_PREDICTION		0x5d00

/* Key 2: Not ready */
#define ASC_CAUSASC_NOT_REPORTABLE		0x0400
#define ASC_BECOMING_READY			0x0401
#define ASC_INITIALIZING_REQUIRED		0x0402
#define ASC_CLEANING_CART_INSTALLED		0x3003
#define ASC_CLEANING_FAILURE			0x3007
#define ASC_MEDIUM_NOT_PRESENT			0x3a00
#define ASC_LOGICAL_UNIT_NOT_CONFIG		0x3e00

/* Key 3: Medium Errors */
#define ASC_WRITE_ERROR			0x0c00
#define ASC_UNRECOVERED_READ			0x1100
#define ASC_RECORDED_ENTITY_NOT_FOUND		0x1400
#define ASC_UNKNOWN_FORMAT			0x3001
#define ASC_IMCOMPATIBLE_FORMAT		0x3002
#define ASC_MEDIUM_FORMAT_CORRUPT		0x3100
#define ASC_SEQUENTIAL_POSITION_ERR		0x3b00
#define ASC_WRITE_APPEND_ERR			0x5000
#define ASC_CARTRIDGE_FAULT			0x5200
#define ASC_MEDIA_LOAD_OR_EJECT_FAILED		0x5300

/* Key 4: Hardware Failure */
#define ASC_COMPRESSION_CHECK			0x0c04
#define ASC_DECOMPRESSION_CRC			0x110d
#define ASC_MECHANICAL_POSITIONING_ERROR	0x1501
#define ASC_MANUAL_INTERVENTION_REQ		0x0403
#define ASC_HARDWARE_FAILURE			0x4000
#define ASC_INTERNAL_TGT_FAILURE		0x4400
#define ASC_ERASE_FAILURE			0x5100

/* Key 5: Illegal Request */
#define ASC_PARAMETER_LIST_LENGTH_ERR		0x1a00
#define ASC_INVALID_OP_CODE			0x2000
#define ASC_INVALID_FIELD_IN_CDB		0x2400
#define ASC_LUN_NOT_SUPPORTED			0x2500
#define ASC_INVALID_FIELD_IN_PARMS		0x2600
#define ASC_SAVING_PARMS_UNSUP			0x3900
#define ASC_MEDIUM_DEST_FULL			0x3b0d
#define ASC_MEDIUM_SRC_EMPTY			0x3b0e
#define ASC_POSITION_PAST_BOM			0x3b0c
#define ASC_MEDIUM_REMOVAL_PREVENTED		0x5302
#define ASC_BAD_MICROCODE_DETECTED		0x8283

/* Key 6: Unit Attention */
#define ASC_NOT_READY_TO_TRANSITION		0x2800
#define ASC_POWERON_RESET			0x2900
#define ASC_MODE_PARAMETERS_CHANGED		0x2a01
#define ASC_INSUFFICIENT_TIME_FOR_OPERATION	0x2e00
#define ASC_MICROCODE_DOWNLOADED		0x3f01
#define ASC_FAILURE_PREDICTION_FALSE		0x5dff
#define ASC_INQUIRY_DATA_HAS_CHANGED		0x3f03

/* Data Protect */
#define ASC_WRITE_PROTECT			0x2700
#define ASC_MEDIUM_OVERWRITE_ATTEMPTED		0x300c
