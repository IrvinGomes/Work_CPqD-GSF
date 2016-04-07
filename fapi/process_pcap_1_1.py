#!/usr/bin/python

import csv
import glob
import sys, getopt
import time
import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from subprocess import call

BIN_TSHARK='/home/cpqd/tools/wireshark/wireshark-1.9.2/install_dir/bin/tshark'

HEX = 'x'

#############################################################
SYNTAX = """syntax process_pcap.py <msg_type> <file/dir>
    - msg_type:  message to be processed
                 values: - cqi_ind
                         - ulsch_ind
                         - dci0_req
                         - all
    - file/dir:  file or directory to be processed
"""

##################################################################################################
# Dictionaries section

PCAP_FIELD_NAME = 2
PCAP_FIELD_UNIT = 3
STR_PLOT_AXIS   = 4
STR_MIN_VAL     = 5
STR_MAX_VAL     = 6

DICT_REM_LEN = 2

####### CQI_INDICATION message ########
DICT_CQI_IND = { 0: ['frame.time_relative',                       'u', 'Time',            ' [s]',   'time'              ],
                 1: ['L1.FAPI_cqiPduIndication_st.rnti',          HEX, 'RNTI',            '',       'rnti'              ],
                 2: ['L1.FAPI_cqiPduIndication_st.timingAdvance', HEX, 'Timing_Advance',  '',       'ta',       0,  63  ],
                 3: ['L1.FAPI_cqiPduIndication_st.ulCqi',         HEX, 'UCI_SNR',         ' [dB]',  'ulsnr',  -65,  65  ],
                 4: ['L1.FAPI_rxCqiIndication_st.pduBuffer',      HEX, 'CQI',             '',       'cqi',      0,  15  ],
                 'filter': ['(L1.lte_phy_header.msgId == 0x8b) && (L1.FAPI_rxCqiIndication_st.numOfCqi == 0x0001)'],
                 'id': ['cqi_ind'] }

DICT_CQI_IND_PDU_BUFFER = { 0: 0,    # 0x00
                            1: 8,    # 0x01
                            2: 4,    # 0x02
                            3: 12,   # 0x03
                            4: 2,    # 0x04
                            5: 10,   # 0x05
                            6: 6,    # 0x06
                            7: 14,   # 0x07
                            8: 1,    # 0x08
                            9: 9,    # 0x09
                            10: 5,   # 0x0a
                            11: 13,  # 0x0b
                            12: 3,   # 0x0c
                            13: 11,  # 0x0d
                            14: 7,   # 0x0e
                            15: 15 } # 0x0f

#############################################################
def create_filtered_pcap_file(str_pcap_base_file, str_pcap_filter, str_pcap_result_file ):
    call([BIN_TSHARK, "-r", str_pcap_base_file, "-R", str_pcap_filter, "-w", str_pcap_result_file ])

#############################################################
def create_csv_file( dict_var, str_pcap_file, str_csv_result_file ):
    cmd_csv_create=BIN_TSHARK + " -T fields -n -r " + str_pcap_file + " -E separator=, "
    dict_len = len( dict_var ) - DICT_REM_LEN
    for i in range(0, dict_len):
        cmd_csv_create += " -e " + dict_var[i][0]
    cmd_csv_create += " > " + str_csv_result_file
    os.system(cmd_csv_create)


#############################################################
def process_csv_file( str_csv_data_file, dict_var ):
    new_rows = []
    with open(str_csv_data_file, 'rb') as f:
        reader = csv.reader(f)
        for row in reader:
            for column in range(0, len(dict_var) - DICT_REM_LEN ):
                if row[column] == "":
                    row[column] = 0
                elif dict_var[column][1] == HEX:
                    row[column] = int(row[column], 16)
            new_rows.append(row)

    # CQI INDICATION exception
    if dict_var['id'][0] == DICT_CQI_IND['id'][0]:
        new_rows_aux = new_rows
        new_rows = []
        for row in new_rows_aux:
            row[3] = (row[3] - 128) / 2                  # Processing UL CQI to UL SNR
            row[4] = DICT_CQI_IND_PDU_BUFFER[ row[4] ]   # Processing PDU Buffer to CQI
            new_rows.append(row)

    with open(str_csv_data_file, 'wb') as f:
        writer = csv.writer(f)
        writer.writerows(new_rows)

#############################################################
def plot_from_csv_file( str_csv_data_file, str_fig_data_file, dict_var, int_axis_x, int_axis_y, str_plot_opt ):
    str_plot_names = []
    for i in range( 0, len(dict_var) - DICT_REM_LEN ) :
        str_plot_names.append( dict_var[ i ][ PCAP_FIELD_NAME ] )
    with open(str_csv_data_file, 'rb') as f:
        vecint_data = np.genfromtxt( str_csv_data_file, delimiter=',', skip_header=0, skip_footer=0, names=str_plot_names )
        if not vecint_data.size:
            print "Found empty csv file"
            return
        fig = plt.figure(figsize=(16,9))
        ax1 = fig.add_subplot(111)
        ax1.set_title( dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] + ' x ' + dict_var[ int_axis_y ][ PCAP_FIELD_NAME ] )
        ax1.set_xlabel( dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] + dict_var[ int_axis_x ][ PCAP_FIELD_UNIT ] )
        ax1.set_ylabel( dict_var[ int_axis_y ][ PCAP_FIELD_NAME ] + dict_var[ int_axis_y ][ PCAP_FIELD_UNIT ] )
        ax1.set_ylim( dict_var[int_axis_y][STR_MIN_VAL], dict_var[int_axis_y][STR_MAX_VAL] + 1)
        ax1.plot( vecint_data[ dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] ], vecint_data[ dict_var[ int_axis_y ][ PCAP_FIELD_NAME ] ], str_plot_opt )
        plt.xticks( np.arange( min( vecint_data[ dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] ] ), max( vecint_data[ dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] ] ) + 1, 1.0) )
        if( (dict_var == DICT_CQI_IND and int_axis_y == 3) )  or ( (dict_var == DICT_ULSCH_IND) and ( int_axis_y == 4 ) ):
            plt.yticks( np.arange(  dict_var[int_axis_y][STR_MIN_VAL],  dict_var[int_axis_y][STR_MAX_VAL] + 1, 5.0) )
        else:
            plt.yticks( np.arange(  dict_var[int_axis_y][STR_MIN_VAL],  dict_var[int_axis_y][STR_MAX_VAL] + 1, 1.0) )
        plt.grid()
        plt.savefig( str_fig_data_file )
        plt.close()
        #plt.show()
        #time.sleep(10)

#############################################################
def plot_with_num_from_csv_file( str_csv_data_file, str_fig_data_file, dict_var, int_axis_x, int_axis_y, int_annot, str_plot_opt ):
    str_plot_names = []
    for i in range( 0, len(dict_var) - DICT_REM_LEN ):
        str_plot_names.append( dict_var[ i ][ PCAP_FIELD_NAME ] )
    with open(str_csv_data_file, 'rb') as f:
        vecint_data = np.genfromtxt( str_csv_data_file, delimiter=',', skip_header=0, skip_footer=0, names=str_plot_names )
        if not vecint_data.size:
            print "Found empty csv file"
            return
        fig = plt.figure(figsize=(16,9))
        ax1 = fig.add_subplot(111)
        ax1.set_title( dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] + ' x ' + dict_var[ int_axis_y ][ PCAP_FIELD_NAME ] )
        ax1.set_xlabel( dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] + dict_var[ int_axis_x ][ PCAP_FIELD_UNIT ] )
        ax1.set_ylabel( dict_var[ int_axis_y ][ PCAP_FIELD_NAME ] + dict_var[ int_axis_y ][ PCAP_FIELD_UNIT ] )
        ax1.set_ylim( dict_var[int_axis_y][STR_MIN_VAL], dict_var[int_axis_y][STR_MAX_VAL] + 1)
        ax1.plot( vecint_data[ dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] ], vecint_data[ dict_var[ int_axis_y ][ PCAP_FIELD_NAME ] ], str_plot_opt )
        plt.xticks( np.arange( min( vecint_data[ dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] ] ), max( vecint_data[ dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] ] ) + 1, 1.0) )
        if( (dict_var == DICT_CQI_IND and int_axis_y == 3) )  or ( (dict_var == DICT_ULSCH_IND) and ( int_axis_y == 4 ) ):
            plt.yticks( np.arange(  dict_var[int_axis_y][STR_MIN_VAL],  dict_var[int_axis_y][STR_MAX_VAL] + 1, 5.0) )
        else:
            plt.yticks( np.arange(  dict_var[int_axis_y][STR_MIN_VAL],  dict_var[int_axis_y][STR_MAX_VAL] + 1, 1.0) )

        for x in len( vecint_data[ dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] ] ):
            ax.annotate( str( vecint_data[ dict_var[ int_annot ][ PCAP_FIELD_NAME ] ] [ x ] ), xy=( vecint_data[ dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] ] [ x ], vecint_data[ dict_var[ int_axis_y ][ PCAP_FIELD_NAME ] ] [ x ] +0.5 ) )

        plt.grid()
        plt.savefig( str_fig_data_file )
        plt.close()

#############################################################
def plot_graph_3axis_from_csv_file( str_csv_data_file_1, str_csv_data_file_2, str_fig_data_file, dict_var_1, dict_var_2, int_axis_x1, int_axis_x2, int_axis_y1, int_axis_y2, str_plot_y1_opt, str_plot_y2_opt ):
    str_plot_names_1 = []
    for i in range( 0, len(dict_var_1) - DICT_REM_LEN ) :
        str_plot_names_1.append( dict_var_1[ i ][ PCAP_FIELD_NAME ] )
    with open(str_csv_data_file_1, 'rb') as f:
        fig = plt.figure(figsize=(16,9))
        ax1 = fig.add_subplot(111)
        vecint_data_1 = np.genfromtxt( str_csv_data_file_1, delimiter=',', skip_header=0, skip_footer=0, names=str_plot_names_1 )
        if not vecint_data_1.size:
            print "Found empty csv file"
            return
        ax1.set_title( dict_var_1[ int_axis_x1 ][ PCAP_FIELD_NAME ] + ' x ' + dict_var_1[ int_axis_y1 ][ PCAP_FIELD_NAME ] + ' x ' + dict_var_2[ int_axis_y2 ][ PCAP_FIELD_NAME ]  )
        ax1.set_xlabel( dict_var_1[ int_axis_x1 ][ PCAP_FIELD_NAME ] + dict_var_1[ int_axis_x1 ][ PCAP_FIELD_UNIT ] )
        ax1.set_ylabel( dict_var_1[ int_axis_y1 ][ PCAP_FIELD_NAME ] + dict_var_1[ int_axis_y1 ][ PCAP_FIELD_UNIT ] )
        ax1.plot( vecint_data_1[ dict_var_1[ int_axis_x1 ][ PCAP_FIELD_NAME ] ], vecint_data_1[ dict_var_1[ int_axis_y1 ][ PCAP_FIELD_NAME ] ], str_plot_y1_opt )

    str_plot_names_2 = []
    for i in range( 0, len(dict_var_2) - DICT_REM_LEN ) :
        str_plot_names_2.append( dict_var_2[ i ][ PCAP_FIELD_NAME ] )
    with open(str_csv_data_file_2, 'rb') as f:
        ax2 = ax1.twinx()
        vecint_data_2 = np.genfromtxt( str_csv_data_file_2, delimiter=',', skip_header=0, skip_footer=0, names=str_plot_names_2 )
        if not vecint_data_2.size:
            print "Found empty csv file"
            return
        ax2.set_ylabel( dict_var_2[ int_axis_y2 ][ PCAP_FIELD_NAME ] + dict_var_2[ int_axis_y2 ][ PCAP_FIELD_UNIT ] )
        ax2.plot( vecint_data_2[ dict_var_2[ int_axis_x2 ][ PCAP_FIELD_NAME ] ], vecint_data_2[ dict_var_2[ int_axis_y2 ][ PCAP_FIELD_NAME ] ], str_plot_y2_opt )

    plt.xticks( np.arange( min( vecint_data_1[ dict_var_1[ int_axis_x1 ][ PCAP_FIELD_NAME ] ] ), max( vecint_data_1[ dict_var_1[ int_axis_x1 ][ PCAP_FIELD_NAME ] ] ) + 1, 1.0) )
    plt.grid()
    plt.savefig( str_fig_data_file )
    plt.close()

#############################################################
def plot_hist_from_csv( str_csv_data_file, str_fig_data_file, dict_var, int_axis_x ):
    str_plot_names = []
    for i in range( 0, len(dict_var) - DICT_REM_LEN ) :
        str_plot_names.append( dict_var[ i ][ PCAP_FIELD_NAME ] )
    with open(str_csv_data_file, 'rb') as f:
        vecint_data = np.genfromtxt( str_csv_data_file, delimiter=',', skip_header=0, skip_footer=0, names=str_plot_names )
        if not vecint_data.size:
            print "Found empty csv file"
            return
        fig = plt.figure(figsize=(16,9))
        ax1 = fig.add_subplot(111)
        ax1.set_title( dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] + dict_var[ int_axis_x ][ PCAP_FIELD_UNIT ] )
        plt.xlabel("Value")
        plt.ylabel("Frequency")
        ax1.set_xlim( dict_var[int_axis_x][STR_MIN_VAL] - 1, dict_var[int_axis_x][STR_MAX_VAL] + 2 )
        #ax1.set_xlabel( dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] + dict_var[ int_axis_x ][ PCAP_FIELD_UNIT ] )
        plt.hist( vecint_data[ dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] ], bins=( np.arange(dict_var[int_axis_x][STR_MIN_VAL] - 1, dict_var[int_axis_x][STR_MAX_VAL] + 2, 1) - 0.5) , width=1, normed=True )
        if( (dict_var == DICT_CQI_IND and int_axis_x == 3) )  or ( (dict_var == DICT_ULSCH_IND) and ( int_axis_x == 4 ) ):
            plt.xticks( np.arange( dict_var[int_axis_x][STR_MIN_VAL], dict_var[int_axis_x][STR_MAX_VAL] + 1, 5.0) )
        else:
            plt.xticks( np.arange( dict_var[int_axis_x][STR_MIN_VAL], dict_var[int_axis_x][STR_MAX_VAL] + 1, 1.0) )
        plt.axvline( vecint_data[ dict_var[ int_axis_x ][ PCAP_FIELD_NAME ] ].mean(), color='r', linestyle='dashed', linewidth=2)
        plt.grid()
        plt.savefig( str_fig_data_file )
        plt.close()

#############################################################
def merge_csv_files( str_folder_name, str_out_file ):
    fout = open( str_out_file,"a" )
    filelist = glob.glob( str_folder_name + '/*.csv' )
    # first file:
    for filename in filelist:
        if str_out_file != filename:
            with open(filename, 'rb') as f:
                for line in f:
                    fout.write(line)
    fout.close()

#############################################################
def plot_cqi_ind_from_csv_file( str_csv_data_file, str_proc_pcap_file, str_img_type, dict_var ):
    plot_from_csv_file( str_csv_data_file, str_proc_pcap_file + '.' + dict_var[0][STR_PLOT_AXIS] + '_' + dict_var[3][STR_PLOT_AXIS]  + '.' + str_img_type, dict_var, 0, 3, 'b-' )
    plot_from_csv_file( str_csv_data_file, str_proc_pcap_file + '.' + dict_var[0][STR_PLOT_AXIS] + '_' + dict_var[4][STR_PLOT_AXIS]  + '.' + str_img_type, dict_var, 0, 4, 'b-' )
    plot_hist_from_csv( str_csv_data_file, str_proc_pcap_file + '.' +  dict_var[3][STR_PLOT_AXIS] + '_hist' + '.' + str_img_type, dict_var, 3 )
    plot_hist_from_csv( str_csv_data_file, str_proc_pcap_file + '.' +  dict_var[4][STR_PLOT_AXIS] + '_hist' + '.' + str_img_type, dict_var, 4 )
    #plot_graph_3axis_from_csv_file( str_csv_data_file, str_csv_data_file,  str_proc_pcap_file + '.' + dict_var[0][STR_PLOT_AXIS] + '_' + dict_var[3][STR_PLOT_AXIS]  + '_' + dict_var[4][STR_PLOT_AXIS] + '.' + str_img_type, dict_var, dict_var, 0, 0, 3, 4, 'b-', 'r-' )

#############################################################
DICT_FUNC_FILE= {
    'cqi_ind':      plot_cqi_ind_from_csv_file,
}

#############################################################
def plot_cqi_ind_all_csv( str_csv_data_file, str_img_type ):
    plot_hist_from_csv( str_csv_data_file, str_csv_data_file  + '.' + str_img_type, DICT_CQI_IND, 3 )
    plot_hist_from_csv( str_csv_data_file, str_csv_data_file  + '.' + str_img_type, DICT_CQI_IND, 4 )

#############################################################
DICT_FUNC_FOLDER = {
    'cqi_ind':      plot_cqi_ind_all_csv,
}

#############################################################
def generate_plot_from_pcap( str_pcap_base_file, str_base_folder, str_dst_folder, dict_var, str_img_type ):
    str_pcap_base_file_fullpath = str_base_folder + '/' + str_pcap_base_file
    str_proc_pcap_file = str_dst_folder + '/' + str_pcap_base_file + '.'  + dict_var['id'][0]
    str_csv_data_file = str_dst_folder + '/' + str_pcap_base_file + '.' + dict_var['id'][0] + '.csv'

    create_filtered_pcap_file( str_pcap_base_file_fullpath, dict_var['filter'][0], str_proc_pcap_file )
    create_csv_file( dict_var, str_proc_pcap_file, str_csv_data_file )
    process_csv_file( str_csv_data_file, dict_var )

    DICT_FUNC_FILE[dict_var['id'][0]]( str_csv_data_file, str_proc_pcap_file, str_img_type, dict_var )

#############################################################
def generate_plots_from_folder( str_base_folder, dict_var, str_img_type ):
    file_list = os.listdir( str_base_folder )
    str_pcap_base_file = ''
    str_dst_folder = str_base_folder + '/' + dict_var['id'][0]
    if not os.path.exists( str_dst_folder ):
         os.makedirs( str_dst_folder )
    for file_name in file_list:
         if os.path.isfile( str_base_folder + '/' + file_name ) == True:
             generate_plot_from_pcap( file_name, str_base_folder, str_dst_folder, dict_var, str_img_type )

    merge_csv_files( str_dst_folder, str_dst_folder + '/' +  dict_var['id'][0] + '_all.csv' )
    DICT_FUNC_FOLDER[dict_var['id'][0]]( str_dst_folder + '/' +  dict_var['id'][0] + '_all.csv', str_img_type )


#############################################################
def main(argv):

    bool_use_all = False
    bool_is_dir = False
    bool_is_file = False
    str_img_type = 'png'
    str_msg_type = ''
    dict_gl_var = DICT_CQI_IND
    func_call = generate_plot_from_pcap

    try:
        opts, args = getopt.getopt(argv,"hcd:f:i:m:",["help","clean","dir=","file=","img=","msg="])
    except getopt.GetoptError:
        print 'ERROR: invalid option'
        print SYNTAX
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            # TODO: improve the help
            print SYNTAX
            sys.exit()
        elif opt in ("-d", "--dir="):
            if os.path.isdir( arg ) == True:
                bool_is_dir = True
                str_parse_art = arg
            else:
                print 'ERROR: it is not a directory'
                print SYNTAX
                sys.exit(2)
        elif opt in ("-f", "--file="):
            if os.path.isfile( arg ) == True:
                bool_is_dir = True
                str_parse_art = arg
            else:
                print 'ERROR: it is not a directory'
                print SYNTAX
                sys.exit(2)
        elif opt in ("-i", "--img="):
            if arg in ('png', 'pdf'):
                str_img_type = arg
            else:
                print 'ERROR: invalid image type'
                print SYNTAX
        elif opt in ("-m", "--msg="):
            if arg in ('cqi_ind', 'ulsch_ind', 'dci0_req', 'all'):
                str_msg_type = arg
                if arg == 'cqi_ind':
                    dict_gl_var = DICT_CQI_IND
                elif arg == 'ulsch_ind':
                    dict_gl_var = DICT_ULSCH_IND
                elif arg == 'dci0_req':
                    dict_gl_var = DICT_DCI0_REQ
                elif arg == 'all':
                    bool_use_all = True
            else:
                print 'ERROR: invalid msg type'
                print SYNTAX
                sys.exit(2)

    if bool_is_dir == False and bool_is_file == False:
        print 'ERROR: no file or directory was specified'
        print SYNTAX
        sys.exit(2)

    if bool_is_dir == True and bool_is_file == True:
        print 'ERROR: cannot specify file and directory simultaneously'
        print SYNTAX
        sys.exit(2)

    if str_msg_type == '':
        print 'ERROR:msg type was not specified'
        print SYNTAX
        sys.exit(2)

    if bool_is_dir == True:
        func_call = generate_plots_from_folder

    if bool_use_all == False:
        func_call(sys.argv[2], dict_gl_var, str_img_type)
    else:
        func_call(sys.argv[2], DICT_ULSCH_IND, str_img_type)
        func_call(sys.argv[2], DICT_CQI_IND, str_img_type)
        func_call(sys.argv[2], DICT_DCI0_REQ, str_img_type)

if __name__ == "__main__":
    main(sys.argv[1:])

# TODO: separate csv entries in more than oneline (lines with more than one entry
#create_filtered_pcap_file( '/home/cpqd/users/gneto/logs/handover/test_ue_handover_sem_mod_220515.pcapng', DICT_RACH_IND['filter'][0], '/tmp/test.pcap' )
#create_csv_file( DICT_RACH_IND, '/tmp/test.pcap', '/tmp/test.csv' )
#plot_with_num_from_csv_file(  '/tmp/test.csv', '/tmp/test.png', DICT_RACH_IND, 0, 3, 2, 'bo' )
