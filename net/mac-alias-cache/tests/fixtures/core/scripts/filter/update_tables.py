    parser.add_argument('--aliases', help='aliases to update (targetted), comma separated', type=lambda x: x.split(','))
            cnt_alias_pf_content = alias.get_pf_addr_count() if to_update is None else cnt_alias_content
