--The Ketje authenticated encryption scheme, designed by Guido Bertoni,
--Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer.
--For more information, feedback or questions, please refer to our website:
--http://ketje.noekeon.org/

-- Implementation by the designers,
-- hereby denoted as "the implementer".

-- To the extent possible under law, the implementer has waived all copyright
-- and related or neighboring rights to the source code in this file.
-- http://creativecommons.org/publicdomain/zero/1.0/

library ieee;
use ieee.std_logic_1164.all;
use IEEE.NUMERIC_STD.all;

library work;
	use work.ketjev2_globals.all;

entity ketjemjv2 is
    port (

        clk             : in  std_logic;
        rst             : in  std_logic;

        din             : in  std_logic_vector(256       -1 downto 0);
		din_size		: in std_logic_vector(5 downto 0);
        go		        : in  std_logic;
        -- type of input/operation
		soft_reset      : in std_logic;
        suv       		: in std_logic;
        auth_data       : in std_logic;
        data      		: in std_logic;
        decrypt         : in std_logic;
        tag       		: in std_logic;
        tag_p_one       : in std_logic;
		last			: in std_logic;
        
        hash		    : in  std_logic;
		squeeze		    : in  std_logic;
        
        -- output
        dout            : out std_logic_vector(256      -1 downto 0);
		dout_size		: out std_logic_vector(5 downto 0);
        dout_valid      : out std_logic;
        ready       	: out  std_logic
    );
end entity ketjemjv2;

architecture structure of ketjemjv2 is

-- components

component ketjev2_round is
port (
    round_in     : in  k_state;
    round_constant_signal    : in std_logic_vector(N-1 downto 0);
    round_out    : out k_state);
end component;

component ketjev2_pi is
port (
    round_in     : in  k_state;
    round_out    : out k_state);
end component;

component ketjev2_inversepi is
port (
    round_in     : in  k_state;    
    round_out    : out k_state);
end component;

--signals
type fsm_state_type is (s_idle,  s_permute_hash, s_permute_stride, s_permute_suv);

signal state,nstate: fsm_state_type;

signal round_const: std_logic_vector(N-1 downto 0);
signal round_constant_signal_64: std_logic_vector(63 downto 0);
signal counter_nr_rounds,n_counter_nr_rounds : unsigned(4 downto 0);
signal n_counter_words, counter_words: unsigned (4 downto 0);
signal round_number : unsigned(4 downto 0);
signal reg_data,round_in,round_out,f_round_in,pi_out,invpi_in,invpi_out: k_state;

signal ready_internal: std_logic;

signal absorb_ad,absorb_decryption: std_logic;
signal absorb_data_vector,bdi_vector: std_logic_vector((5*5*N)-1 downto 0);
signal frame_bits: std_logic_vector(3 downto 0);

signal frame_bits_position: std_logic_vector(3 downto 0);

signal reset_reg_data: std_logic;


signal bdi_ready_internal: std_logic;

signal is_decrypt   : std_logic;
signal no_previous_message, reset_no_previous_message, set_no_previous_message : std_logic;
signal sampled_decrypt:std_logic;
signal din_internal: std_logic_vector(255 downto 0);
signal sample_permutation_out,sample_permutationstar_out: std_logic;
signal suv_state_shift : std_logic;
signal dout_reg: std_logic_vector(255 downto 0);
signal squeeze_state_shift,sample_dout,n_dout_valid, sample_dout_valid,sample_dout_decryption,sample_dout_piout: std_logic;
signal dout_size_reg,n_dout_size_reg,din_size_sampled: std_logic_vector(5 downto 0);

begin

--port map of components

ketje_round_i: ketjev2_round port map (f_round_in,round_const,round_out );

ketje_pi_i: ketjev2_pi port map (round_out,pi_out );

ketje_invpi_i: ketjev2_inversepi port map (invpi_in,invpi_out );
	
-- swap input for endianess
i001:for i in 0 to 31 generate
		din_internal((255 - (i*8)) downto (248 - (i*8))) <= din((i+1)*8-1 downto i*8);

     end generate;


    --! =======================================================================
    --! registers
    --! =======================================================================

	process(clk, rst)
        begin
            if (rst = '1') then
                state <= s_idle;
				is_decrypt <= '0';
				counter_nr_rounds <= (others => '0');				
				counter_words <= (others => '0');				
				sampled_decrypt <= '0';
				no_previous_message <= '0';
				dout_reg<= (others => '0');	
				dout_size_reg <= (others => '0');
				din_size_sampled <= (others => '0');	
				sample_dout_valid <= '0';	
				dout_valid <= '0';				

				for row in 0 to 4 loop
					for col in 0 to 4 loop
						for i in 0 to N-1 loop
							reg_data(row)(col)(i)<='0';
						end loop;
					end loop;
				end loop;				
            elsif rising_edge(clk) then
				counter_words <= n_counter_words after k_seq_dly;
				counter_nr_rounds <= n_counter_nr_rounds after k_seq_dly;
				state <= nstate after k_seq_dly;
				sample_dout_valid <= n_dout_valid after k_seq_dly;				
				dout_valid <= n_dout_valid after k_seq_dly;

				if (reset_reg_data='1') then
					for row in 0 to 4 loop
						for col in 0 to 4 loop
							for i in 0 to N-1 loop
								reg_data(row)(col)(i)<='0' after k_seq_dly;
							end loop;
						end loop;
					end loop;

				end if;			

				
				
				if(suv_state_shift='1') then
				
					for i in 0 to N-1 loop
						reg_data(4)(4)(i) <= reg_data(0)(0)(i) xor din(i) after k_seq_dly;
					end loop;
					
					for row in 0 to 3 loop
						for i in 0 to N-1 loop
							reg_data(row)(4)(i)<=reg_data(row+1)(0)(i) after k_seq_dly;
						end loop;
					end loop;
					

					for row in 0 to 4 loop
						for col in 0 to 3 loop
							for i in 0 to N-1 loop
								reg_data(row)(col)(i)<=reg_data(row)(col+1)(i) after k_seq_dly;
							end loop;
						end loop;
					end loop;
				elsif(sample_permutation_out='1') then
					reg_data<=round_out after k_seq_dly;	
				elsif(sample_permutationstar_out='1') then
					reg_data<=pi_out after k_seq_dly;					
				elsif(squeeze_state_shift='1') then
				
					for i in 0 to N-1 loop
						reg_data(4)(4)(i) <= reg_data(0)(0)(i) after k_seq_dly;
					end loop;
					
					for row in 0 to 3 loop
						for i in 0 to N-1 loop
							reg_data(row)(4)(i)<=reg_data(row+1)(0)(i) after k_seq_dly;
						end loop;
					end loop;
					

					for row in 0 to 4 loop
						for col in 0 to 3 loop
							for i in 0 to N-1 loop
								reg_data(row)(col)(i)<=reg_data(row)(col+1)(i) after k_seq_dly;
							end loop;
						end loop;
					end loop;
					for i in 0 to 7 loop
						dout_reg(i) <= round_in(0)(0)(i)  after k_seq_dly;
						dout_reg(i+8) <= round_in(0)(1)(i)  after k_seq_dly;
						dout_reg(i+16) <= '0' after k_seq_dly;
						dout_reg(i+24) <= '0' after k_seq_dly;
						
					end loop;
				
				end if;
				if(sample_dout ='1') then
					for col in 0 to 3 loop					
						for j in 0 to 7 loop
							for i in 0 to 7 loop
								dout_reg(256-8+i -8*j- col*N) <= round_in(0)(col)(i+8*j)  after k_seq_dly;
							end loop;				
						end loop;					
					end loop;
				end if;
				if(sample_dout_decryption ='1') then

					for col in 0 to 3 loop					
						for j in 0 to 7 loop
							for i in 0 to 7 loop
								dout_reg(256-8+i -8*j- col*N) <= reg_data(0)(col)(i+8*j) xor round_in(0)(col)(i+8*j) after k_seq_dly;
							end loop;				
						end loop;					
					end loop;
				end if;
				
				if(sample_dout_piout ='1') then
					for col in 0 to 3 loop					
						for j in 0 to 7 loop
							for i in 0 to 7 loop
								dout_reg(256-8+i -8*j- col*N) <= pi_out(0)(col)(i+8*j)  after k_seq_dly;
							end loop;				
						end loop;					
					end loop;	
				end if;
				if(n_dout_valid ='1') then
					dout_size_reg <= n_dout_size_reg after k_seq_dly;
				end if;

			
				
				-- last should be managed? see in auth_data value of frame bit position
				if( go='1' and (data ='1' or auth_data='1' or suv ='1')) then
					din_size_sampled <= din_size after k_seq_dly;
				else
					din_size_sampled <=(others=>'0') after k_seq_dly;
				end if;
            end if;
        end process;

	
	
 -- main process for next state and control signals
 
  p_main : process( 
        state, din,  counter_nr_rounds,counter_words,reg_data,round_in,invpi_out,round_out,pi_out,go, suv, tag, tag_p_one, auth_data, data, decrypt, soft_reset, hash, squeeze)		
  
  begin
		-- default values
		squeeze_state_shift <='0' after k_seq_dly;
		suv_state_shift <='0' after k_seq_dly;
		ready_internal <='0' after k_seq_dly;
		sample_permutation_out <='0' after k_seq_dly;
		sample_permutationstar_out <='0' after k_seq_dly;
		sample_dout_decryption <='0' after k_seq_dly;
		
		--frame_bits_position <= "1000" after k_seq_dly;
		frame_bits <="0000" after k_seq_dly;
		
		reset_reg_data <='0' after k_seq_dly;
		
		n_counter_nr_rounds <= counter_nr_rounds after k_seq_dly;
		n_counter_words <= counter_words after k_seq_dly;
						
				
		nstate <= s_idle after k_seq_dly;
		absorb_ad <= '0' after k_seq_dly;
		ready <='0' after k_seq_dly;
		sample_dout <='0' after k_seq_dly;
		n_dout_valid <= '0' after k_seq_dly;
		invpi_in <= round_in after k_seq_dly;
		f_round_in <= invpi_out after k_seq_dly;
		sample_dout_piout <= '0' after k_seq_dly;
		n_dout_size_reg <= (others=> '0');
		absorb_decryption <='0' after k_seq_dly;

		
		case state is	
			when s_idle =>
				ready <='1' after k_seq_dly;
				nstate <= s_idle after k_seq_dly;
				if(go='1') then
					if(soft_reset='1') then
						nstate <= s_idle after k_seq_dly;
						reset_reg_data <='1' after k_seq_dly;
						n_counter_words <= "00000" after k_seq_dly;
					elsif(hash='1') then
						if(counter_words="11001") then
							--enough to compute a permutation
							n_counter_words <= "00000" after k_seq_dly;
							n_counter_nr_rounds <= "00001" after k_seq_dly;
							nstate <= s_permute_hash after k_seq_dly;
							ready <='0' after k_seq_dly;
						else
							-- absorb the input in state register
							suv_state_shift <='1' after k_seq_dly;
							
							-- increment counter							
							n_counter_words <= counter_words + 1 after k_seq_dly; 
							nstate <= s_idle after k_seq_dly;
						end if;
					elsif(squeeze='1') then
						if(counter_words="11001") then
							n_counter_words <= "00000" after k_seq_dly;
							n_counter_nr_rounds <= "00001" after k_seq_dly;
							nstate <= s_permute_hash after k_seq_dly;
						else
							-- give output
							squeeze_state_shift <='1' after k_seq_dly;
							-- increment counter
							n_counter_words <= counter_words + 1 after k_seq_dly; 
							nstate <= s_idle after k_seq_dly;
							n_dout_valid <= '1' after k_seq_dly;	
						
						end if;
					elsif(suv='1') then	
						if(counter_words="11000") then
							--enough, compute a permutation
							suv_state_shift <='1' after k_seq_dly;
							n_counter_words <= "00000" after k_seq_dly;
							n_counter_nr_rounds <= "01011" after k_seq_dly;
							nstate <= s_permute_suv after k_seq_dly;
							ready <= '0' after k_seq_dly;
						else
							nstate <= s_idle after k_seq_dly;
							suv_state_shift <='1' after k_seq_dly;
							n_counter_words <= counter_words + 1 after k_seq_dly; 						
						end if;					
						
					elsif(auth_data='1') then	
						if(last='0') then
							n_counter_words <= "00000" after k_seq_dly;
							n_counter_nr_rounds <= "10111" after k_seq_dly;
							nstate <= s_idle  after k_seq_dly;
							absorb_ad <='1' after k_seq_dly;
							sample_permutationstar_out <='1' after k_seq_dly;
							-- more AD to come
							--frame_bits_position <= "1000" after k_seq_dly;	
							frame_bits <="1100" after k_seq_dly;
							
						elsif(tag='0') then
							-- no more AD but Data will come
							n_counter_words <= "00000" after k_seq_dly;
							n_counter_nr_rounds <= "10111" after k_seq_dly;
							nstate <= s_idle  after k_seq_dly;
							absorb_ad <='1' after k_seq_dly;
							sample_permutationstar_out <='1' after k_seq_dly;									
							if(din_size = "100000") then
								frame_bits <="1110" after k_seq_dly;
							else
								frame_bits <="0110" after k_seq_dly;
							end if;	
						else -- tag =1
							nstate <= s_permute_stride after k_seq_dly;
							n_counter_nr_rounds <= "10010" after k_seq_dly;		
							
							absorb_ad <='1' after k_seq_dly;
							sample_permutation_out <='1' after k_seq_dly;									
							if(din_size = "100000") then							
								frame_bits <="1110" after k_seq_dly;
							else	
								frame_bits <="0110" after k_seq_dly;
							end if;									
						end if;	
					elsif(data='1') then						
						if(decrypt='0') then
							if(last='0') then
								n_dout_valid <= '1' after k_seq_dly;	
								n_dout_size_reg <= din_size after k_seq_dly;									
								absorb_ad <='1' after k_seq_dly;
								sample_permutationstar_out <='1' after k_seq_dly;
								sample_dout <='1' after k_seq_dly;
								n_counter_nr_rounds <= "10111" after k_seq_dly;							
								nstate <= s_idle  after k_seq_dly;
								if(din_size = "100000") then
									--frame_bits <="1110" after k_seq_dly;
									frame_bits <="1111" after k_seq_dly;
								else
									frame_bits <="0110" after k_seq_dly;
								end if;	

									
							elsif(tag='1') then	
								nstate <= s_permute_stride after k_seq_dly;	
								n_dout_valid <= '1' after k_seq_dly;	
								n_dout_size_reg <= din_size after k_seq_dly;								
								absorb_ad <='1' after k_seq_dly;
								sample_permutation_out <='1' after k_seq_dly;

								sample_dout <='1' after k_seq_dly;
								n_counter_nr_rounds <= "10010" after k_seq_dly;							
								if(din_size = "100000") then
									frame_bits <="1101" after k_seq_dly;
								else
									frame_bits <="0101" after k_seq_dly;
								end if;							
								
								
							else
								-- no more data but no tag to be generate
								
								n_dout_valid <= '1' after k_seq_dly;
								n_dout_size_reg <= din_size after k_seq_dly;								
								absorb_ad <='1' after k_seq_dly;
								sample_permutationstar_out <='1' after k_seq_dly;

								sample_dout <='1' after k_seq_dly;
								n_counter_nr_rounds <= "10111" after k_seq_dly;							
								nstate <= s_idle  after k_seq_dly;
								if(din_size = "100000") then
									frame_bits <="1110" after k_seq_dly;
								else
									frame_bits <="0110" after k_seq_dly;
								end if;							
							
							end if;
						
						else
							-- decrypt
							if(last='0') then
								-- perform step
								sample_dout_decryption <='1' after k_seq_dly;
								n_counter_nr_rounds <= "10111" after k_seq_dly;
								-- set frame bits accordingly				
								frame_bits <="1111" after k_seq_dly;
								absorb_decryption <='1' after k_seq_dly;
								absorb_ad <= '0' after k_seq_dly;
								n_dout_valid <= '1' after k_seq_dly;
								n_dout_size_reg <= din_size after k_seq_dly;	
								sample_permutationstar_out <='1' after k_seq_dly;								
							
								nstate <= s_idle after k_seq_dly;								
							elsif(tag='1') then	
								sample_dout_decryption <='1' after k_seq_dly;
								n_counter_nr_rounds <= "10010" after k_seq_dly;
								absorb_decryption <='1' after k_seq_dly;
								absorb_ad <= '0' after k_seq_dly;
								sample_permutation_out <= '1' after k_seq_dly;
								n_dout_valid <= '1' after k_seq_dly;	
								n_dout_size_reg <= din_size after k_seq_dly;								
								nstate <= s_permute_stride after k_seq_dly;		
								-- set frame bits accordingly										
								if(din_size = "100000") then
									frame_bits <="1101" after k_seq_dly;
								else
									frame_bits <="0101" after k_seq_dly;
								end if;	
								
							else
								-- perform step
								sample_dout_decryption <='1' after k_seq_dly;
								n_counter_nr_rounds <= "10111" after k_seq_dly;
								-- set frame bits accordingly				
								absorb_decryption <='1' after k_seq_dly;
								absorb_ad <= '0' after k_seq_dly;
								sample_permutation_out <= '1' after k_seq_dly;
								n_dout_valid <= '1' after k_seq_dly;
								n_dout_size_reg <= din_size after k_seq_dly;								
								nstate <= s_idle after k_seq_dly;		
								if(din_size = "100000") then
									frame_bits <="1101" after k_seq_dly;
								else
									frame_bits <="0101" after k_seq_dly;
								end if;									
							end if;
					
						end if;											

					elsif(tag='1') then					
						--frame_bits_position <= "0000" after k_seq_dly;
						frame_bits <="0110" after k_seq_dly;
						n_counter_words <= "00000" after k_seq_dly;
						n_counter_nr_rounds <= "10010" after k_seq_dly;		
						
						absorb_ad <='1' after k_seq_dly;
						sample_permutation_out <='1' after k_seq_dly;	
						nstate <= s_permute_stride  after k_seq_dly;	
					elsif(tag_p_one='1') then
						n_counter_words <= "00000" after k_seq_dly;
						n_counter_nr_rounds <= "10111" after k_seq_dly;
						absorb_ad <= '1' after k_seq_dly;
						sample_permutationstar_out <='1' after k_seq_dly;
						sample_dout_piout <= '1' after k_seq_dly;
						n_dout_valid <= '1' after k_seq_dly;
						n_dout_size_reg <= "100000" after k_seq_dly;
						--frame_bits_position <= "0000" after k_seq_dly;
						-- perform step					
						frame_bits <="0010" after k_seq_dly;							
						nstate <= s_idle  after k_seq_dly;								
						
					
					end if;
				end if;		
				
			when s_permute_hash =>
				
				n_dout_valid <='0' after k_seq_dly;
				if(counter_nr_rounds = "01100") then
					nstate <= s_idle after k_seq_dly;
				else
					
					f_round_in <= round_in after k_seq_dly;
					sample_permutation_out <='1' after k_seq_dly;
					
					n_counter_nr_rounds <= counter_nr_rounds + 1 after k_seq_dly; 
					nstate <= s_permute_hash after k_seq_dly;
				end if;
		
				
			when s_permute_suv =>
				ready <='0' after k_seq_dly;
				n_dout_valid <='0' after k_seq_dly;
				if(counter_nr_rounds = "10111") then
					nstate <= s_idle after k_seq_dly;
				else
					if(counter_nr_rounds = "01011") then
						f_round_in <= invpi_out after k_seq_dly;
					else
						f_round_in <= round_in after k_seq_dly;
					end if;
					if(counter_nr_rounds = "10110") then
						sample_permutationstar_out <='1' after k_seq_dly;
					else
						sample_permutation_out <='1' after k_seq_dly;
					end if;				
					n_counter_nr_rounds <= counter_nr_rounds + 1 after k_seq_dly; 
					nstate <= s_permute_suv after k_seq_dly;
				end if;


				

			when s_permute_stride =>
				ready <= '0' after k_seq_dly;
				absorb_decryption <= '0' after k_seq_dly;
				nstate <= s_permute_stride after k_seq_dly;
				n_dout_valid <='0' after k_seq_dly;
				if(counter_nr_rounds = "10111") then
					nstate <= s_idle after k_seq_dly;
					sample_dout <='1' after k_seq_dly;
					n_dout_valid <= '1' after k_seq_dly;
					n_dout_size_reg <= "100000" after k_seq_dly;
				else
					f_round_in <= round_in after k_seq_dly;
					if(counter_nr_rounds = "10110") then
						sample_permutationstar_out <='1' after k_seq_dly;
					else
						sample_permutation_out <='1' after k_seq_dly;
					end if;										
					n_counter_nr_rounds <= counter_nr_rounds + 1 after k_seq_dly; 
				end if;
				


			when others =>
				null;
		end case;
	
  
  end process;
  


absorb_data_vector(7 downto 0) <= ("0000" & frame_bits) when (din_size = "000000") else
									din_internal(7 downto 0);
							
	i0031: for i in 1 to 31 generate
absorb_data_vector((7+8*i) downto 8*i) <= din_internal((7+8*i) downto 8*i) when (unsigned(din_size)>i) else
								("0000" & frame_bits) when unsigned(din_size)=i else
								(others=> '0');
			end generate;



	
-- absorb_data_vector(15 downto 8) <= din_internal(15 downto 8) when (unsigned(din_size_sampled)>1) else
								-- ("0000" & frame_bits) when din_size_sampled="00001" else
								-- (others=> '0');

-- absorb_data_vector(23 downto 16) <= din_internal(23 downto 16) when (unsigned(din_size_sampled)>2) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');
-- absorb_data_vector(31 downto 24) <= din_internal(31 downto 24) when (unsigned(din_size_sampled)>3) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(39 downto 32) <= din_internal(39 downto 32) when (unsigned(din_size_sampled)>4) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(47 downto 40) <= din_internal(47 downto 40) when (unsigned(din_size_sampled)>5) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(55 downto 48) <= din_internal(55 downto 48) when (unsigned(din_size_sampled)>6) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(63 downto 56) <= din_internal(63 downto 56) when (unsigned(din_size_sampled)>7) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(71 downto 64) <= din_internal(71 downto 64) when (unsigned(din_size_sampled)>8) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(79 downto 72) <= din_internal(79 downto 72) when (unsigned(din_size_sampled)>9) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(87 downto 80) <= din_internal(87 downto 80) when (unsigned(din_size_sampled)>10) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(95 downto 88) <= din_internal(95 downto 88) when (unsigned(din_size_sampled)>11) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(103 downto 96) <= din_internal(103 downto 96) when (unsigned(din_size_sampled)>12) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(111 downto 104) <= din_internal(111 downto 104) when (unsigned(din_size_sampled)>13) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');

-- absorb_data_vector(119 downto 112) <= din_internal(119 downto 112) when (unsigned(din_size_sampled)>14) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');								
								
-- absorb_data_vector(127 downto 120) <= din_internal(127 downto 120) when (unsigned(din_size_sampled)>15) else
								-- ("0000" & frame_bits) when din_size_sampled="00010" else
								-- (others=> '0');																

								
absorb_data_vector(259 downto 256) <= frame_bits when (din_size = "100000") else 
								"1000" ;
								
absorb_data_vector(5*5*N-1 downto N*4+4) <= (others=> '0');



bdi_vector(7 downto 0) <= ("0000" & frame_bits) xor (reg_data(0)(0)(7) & reg_data(0)(0)(6) &reg_data(0)(0)(5) &reg_data(0)(0)(4) &reg_data(0)(0)(3) &reg_data(0)(0)(2) &reg_data(0)(0)(1) &reg_data(0)(0)(0) ) when (din_size = "000000") else
					din_internal(7 downto 0);
							

	i0032: for i in 1 to 31 generate
bdi_vector((7+8*i) downto 8*i) <= din_internal((7+8*i) downto 8*i) when (unsigned(din_size)>i) else
								("0000" & frame_bits) xor (reg_data(0)((i*8)/N)(7+(i*8)mod N) & reg_data(0)((i*8)/N)(6+(i*8)mod N) &reg_data(0)((i*8)/N)(5+(i*8)mod N) &reg_data(0)((i*8)/N)(4+(i*8)mod N) &reg_data(0)((i*8)/N)(3+(i*8)mod N) &reg_data(0)((i*8)/N)(2+(i*8)mod N) &reg_data(0)((i*8)/N)(1+(i*8)mod N) &reg_data(0)((i*8)/N)((i*8)mod N)) when unsigned(din_size)=i else
								(others=> '0');
			end generate;
			

bdi_vector(259 downto 256) <= frame_bits when (din_size="100000") else 
								"1000" ;
								
bdi_vector(5*5*N-1 downto N*4+4) <= (others=> '0');

		i0121: for i in 0 to 15 generate
			round_in(0)(0)(i)<= 	(absorb_data_vector(0*5*N+ 0*N+i) xor reg_data(0)(0)(i)) when (absorb_ad='1') else
									bdi_vector(0*5*N+ 0*N+i) when (absorb_decryption='1') else
									reg_data(0)(0)(i);
			round_in(0)(1)(i)<= 	(absorb_data_vector(0*5*N+ 1*N+i) xor reg_data(0)(1)(i)) when (absorb_ad='1') else
									bdi_vector(0*5*N+ 1*N+i) when (absorb_decryption='1' and ((8*unsigned(din_size)+8) > (i+N)))  else
									reg_data(0)(1)(i);
			round_in(0)(2)(i)<= 	(absorb_data_vector(0*5*N+ 2*N+i) xor reg_data(0)(2)(i)) when (absorb_ad='1') else
									bdi_vector(0*5*N+ 2*N+i) when (absorb_decryption='1' and ((8*unsigned(din_size)+8) > (i+2*N)))  else
									reg_data(0)(2)(i);

			round_in(0)(3)(i)<= 	(absorb_data_vector(0*5*N+ 3*N+i) xor reg_data(0)(3)(i)) when (absorb_ad='1') else
									bdi_vector(0*5*N+ 3*N+i) when (absorb_decryption='1' and ((8*unsigned(din_size)+8) > (i+3*N)))  else
									reg_data(0)(3)(i);									
									
		end generate;

		

		i012: for i in 16 to N-1 generate
			round_in(0)(0)(i)<= 	(absorb_data_vector(0*5*N+ 0*N+i) xor reg_data(0)(0)(i)) when (absorb_ad='1') else
									bdi_vector(0*5*N+ 0*N+i) when (absorb_decryption='1' and ((8*unsigned(din_size)+8) > i)) else
									reg_data(0)(0)(i);
			round_in(0)(1)(i)<= 	(absorb_data_vector(0*5*N+ 1*N+i) xor reg_data(0)(1)(i)) when (absorb_ad='1') else
									bdi_vector(0*5*N+ 1*N+i) when (absorb_decryption='1' and ((8*unsigned(din_size)+8) > (i+N)))  else
									reg_data(0)(1)(i);
			round_in(0)(2)(i)<= 	(absorb_data_vector(0*5*N+ 2*N+i) xor reg_data(0)(2)(i)) when (absorb_ad='1') else
									bdi_vector(0*5*N+ 2*N+i) when (absorb_decryption='1' and ((8*unsigned(din_size)+8) > (i+2*N)))  else
									reg_data(0)(2)(i);

			round_in(0)(3)(i)<= 	(absorb_data_vector(0*5*N+ 3*N+i) xor reg_data(0)(3)(i)) when (absorb_ad='1') else
									bdi_vector(0*5*N+ 3*N+i) when (absorb_decryption='1' and ((8*unsigned(din_size)+8) > (i+3*N)))  else
									reg_data(0)(3)(i);									
									
		end generate;
		
		
--	i011: for col in 0 to 1 generate
--		i012: for i in 0 to N-1 generate
--			round_in(0)(col)(i)<= 	(absorb_data_vector(0*5*N+ col*N+i) xor reg_data(0)(col)(i)) when (absorb_ad='1') else
--									bdi_vector(0*5*n+ col*N+i) when (absorb_decryption='1') else
--									reg_data(0)(col)(i);
--		end generate;	
--	end generate;
--


	i0011: for col in 4 to 4 generate
		i0012: for i in 0 to N-1 generate
			round_in(0)(col)(i)<= 	(absorb_data_vector(0*5*N+ col*N+i) xor reg_data(0)(col)(i)) when (absorb_ad='1') else
									(bdi_vector(0*5*n+ col*N+i) xor reg_data(0)(col)(i)) when (absorb_decryption='1') else
									reg_data(0)(col)(i);
		end generate;	
	end generate;

i10: for row in 1 to 4 generate
	i11: for col in 0 to 4 generate
		i12: for i in 0 to N-1 generate
			round_in(row)(col)(i)<=	(absorb_data_vector(row*5*N+ col*N+i) xor reg_data(row)(col)(i)) when (absorb_ad='1') else
									reg_data(row)(col)(i) when (absorb_decryption='1') else
									reg_data(row)(col)(i);
		end generate;	
	end generate;
end generate;


round_constants : process (n_counter_nr_rounds)
begin
	case n_counter_nr_rounds is
        when "00000" => round_constant_signal_64 <= X"0000000000000001" ;
	    when "00001" => round_constant_signal_64 <= X"0000000000008082" ;
	    when "00010" => round_constant_signal_64 <= X"800000000000808A" ;
	    when "00011" => round_constant_signal_64 <= X"8000000080008000" ;
	    when "00100" => round_constant_signal_64 <= X"000000000000808B" ;
	    when "00101" => round_constant_signal_64 <= X"0000000080000001" ;
	    when "00110" => round_constant_signal_64 <= X"8000000080008081" ;
	    when "00111" => round_constant_signal_64 <= X"8000000000008009" ;
	    when "01000" => round_constant_signal_64 <= X"000000000000008A" ;
	    when "01001" => round_constant_signal_64 <= X"0000000000000088" ;
	    when "01010" => round_constant_signal_64 <= X"0000000080008009" ;
	    when "01011" => round_constant_signal_64 <= X"000000008000000A" ;
	    when "01100" => round_constant_signal_64 <= X"000000008000808B" ;
	    when "01101" => round_constant_signal_64 <= X"800000000000008B" ;
	    when "01110" => round_constant_signal_64 <= X"8000000000008089" ;
	    when "01111" => round_constant_signal_64 <= X"8000000000008003" ;
	    when "10000" => round_constant_signal_64 <= X"8000000000008002" ;
	    when "10001" => round_constant_signal_64 <= X"8000000000000080" ;
	    when "10010" => round_constant_signal_64 <= X"000000000000800A" ;
	    when "10011" => round_constant_signal_64 <= X"800000008000000A" ;
	    when "10100" => round_constant_signal_64 <= X"8000000080008081" ;
	    when "10101" => round_constant_signal_64 <= X"8000000000008080" ;
	    when "10110" => round_constant_signal_64 <= X"0000000080000001" ;
	    when "10111" => round_constant_signal_64 <= X"8000000080008008" ;	    	    
	    when others => round_constant_signal_64 <=(others => '0');
        end case;
end process round_constants;

round_const<=round_constant_signal_64(N-1 downto 0);

--output signal
dout <= dout_reg after k_seq_dly;
dout_size <= dout_size_reg after k_seq_dly; 

end structure;
