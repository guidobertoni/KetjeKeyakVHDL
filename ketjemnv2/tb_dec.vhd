
--The Ketje authenticated encryption scheme, designed by Guido Bertoni,
--Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer.
--For more information, feedback or questions, please refer to our website:
--http://ketje.noekeon.org/

-- Implementation by the designers,
-- hereby denoted as "the implementer".

-- To the extent possible under law, the implementer has waived all copyright
-- and related or neighboring rights to the source code in this file.
-- http://creativecommons.org/publicdomain/zero/1.0/

library std;
	use std.textio.all;
	
library ieee;
	use ieee.std_logic_1164.all;
	use IEEE.NUMERIC_STD.all;
	use ieee.std_logic_textio.all;
	
	

library work;
	use work.ketjev2_globals.all;

entity tb2dec_kmj is
end tb2dec_kmj;

architecture tb_dec of tb2dec_kmj is


-- components

component ketjemnv2 is
    port (

        clk             : in  std_logic;
        rst             : in  std_logic;

        din             : in  std_logic_vector(128       -1 downto 0);
		din_size		: in std_logic_vector(4 downto 0);
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
        dout            : out std_logic_vector(128      -1 downto 0);
		dout_size		: out std_logic_vector(4 downto 0);
        dout_valid      : out std_logic;
        ready       	: out  std_logic
    );
end component;

  -- signal declarations

	
signal      clk                  : std_logic;
signal      rst                  : std_logic;
signal din                      : std_logic_vector(127 downto 0);
signal din_size,dout_size				     : std_logic_vector(4 downto 0);
signal go		        		 : std_logic;
signal soft_reset      		 : std_logic;
signal suv       				 : std_logic;
signal auth_data       		 : std_logic;
signal data      				 : std_logic;
signal decrypt         		 : std_logic;
signal tag       				 : std_logic;
signal tag_p_one       		 : std_logic;
signal last       		 : std_logic;
signal hash		    		     : std_logic;
signal squeeze		    		 : std_logic;
signal dout            		 : std_logic_vector(128      -1 downto 0);
signal dout_valid      		 : std_logic;
signal ready                     : std_logic;
signal cnt: unsigned(4 downto 0);
signal counter_delay: unsigned(5 downto 0);

 type st_type is (init,write_ad,buble_ad,write_suv0,write_suv1,write_suv2,write_suv3,write_suv4,write_suv5,
 write_suv6,write_suv7,write_suv8,write_suv9,
 write_suv10,write_suv11,write_suv12,write_suv13,write_suv14,
 write_suv15,write_suv16,write_suv17,write_suv18,write_suv19,write_suv20,
 bubble_p,write_p,bubble_tag,wait_tag,next_tag,stop);
 signal st : st_type;
 
begin  -- Rtl

-- port map
kmn_map : ketjemnv2
    port map (
        clk                  ,
        rst                  ,
din             ,
din_size		,		
go		        ,		
-- type of input		
soft_reset      ,		
suv       		,		
auth_data       ,		
data      		,		
decrypt         ,		
tag       		,		
tag_p_one       ,		
last,		
hash		    ,		
squeeze		    ,		
		
-- output		
dout            ,	
dout_size,	
dout_valid      ,		
ready       			
		
    );



rst <= rst_active, not(rst_active) after 19 ns;

--main process
p_main: process (clk,rst)
variable line_in,line_out : line;
variable num_n : integer;
variable cnt_b : integer;
variable temp: std_logic_vector(7 downto 0);	
variable temp32: std_logic_vector(31 downto 0);	
variable temp128: std_logic_vector(127 downto 0);	
	
	file filein : text open read_mode is "datadeckmn.in";
	file fileout : text open write_mode is "datadeckmn_vhdl.out";
				

begin
	if rst = rst_active then                 -- asynchronous rst_n (active low)
		st <= INIT;
		din <=(others=>'0');
		din_size <= (others=>'0');
		go <= '0';
		soft_reset      <= '0';
		suv       		<= '0';
		auth_data       <= '0';
		data      		<= '0';
		decrypt         <= '1';
		tag       		<= '0';
		tag_p_one       <= '0';		
		hash		    <= '0';
		squeeze		    <= '0';
		last <= '0';
		cnt <= "00000";
		
	elsif clk'event and clk = '1' then  -- rising clk edge

		go <= '0';
		soft_reset      <= '0';
		suv       		<= '0';
		auth_data       <= '0';
		data      		<= '0';
		decrypt         <= '1';
		tag       		<= '0';
		tag_p_one       <= '0';		
		hash		    <= '0';
		squeeze		    <= '0';
		cnt <= "00000";
		
		case st is
			when init =>
				cnt <= "00000"	;
				cnt_b :=0;
				soft_reset<='0' after k_seq_dly;
				go <='0' after k_seq_dly;
				st <= write_suv0 after k_seq_dly;
			when write_suv0 =>
				if(cnt="011001") then
					st <= buble_ad after k_seq_dly;	
					go <='0' after k_seq_dly;
					last <= '0' after k_seq_dly;
				else
					
					go <= '1' after k_seq_dly;
					suv <='1' after k_seq_dly;
					if(cnt = "00000") then
						-- first line is a comment
						readline(filein,line_in);
					end if;

					for i in 0 to 3 loop
						readline(filein,line_in);
						hread(line_in,temp);
						din (i*8+7 downto i*8) <= temp( 7 downto 0) after k_seq_dly;
					end loop;
					
					din(127 downto 32) <= (others => '0') after k_seq_dly;
					last <= '0' after k_seq_dly;
					cnt <= cnt +1;
					if(cnt="011000") then
						last <= '1' after k_seq_dly;
					end if;

				end if;	
				
				
			when buble_ad =>
				last <= '0' after k_seq_dly;
				if(ready='1') then
					-- first line is a comment
					readline(filein,line_in);
					-- second line is the size of AD		
					readline(filein,line_in);	
					read(line_in,num_n);
					
					
					st <= write_ad after k_seq_dly;	
				end if;
			when write_ad=>				
									
				if(ready='1') then
					if(cnt_b+16 < num_n) then						
						go <= '1' after k_seq_dly;
						auth_data <='1' after k_seq_dly;
						
						for i in 0 to 15 loop
							readline(filein,line_in);
							hread(line_in,temp);
							din ( 127- i*8 downto (128-8)-i*8) <= temp( 7 downto 0) after k_seq_dly;
						end loop;
						
						din_size <="10000" after k_seq_dly;				
						last <= '0' after k_seq_dly;	
						cnt_b := cnt_b +4;						
					else 
						din <= (others =>'0');
						for i in 0 to (num_n-cnt_b-1) loop
							readline(filein,line_in);
							hread(line_in,temp);
							din ( 127- i*8 downto (128-8)-i*8) <= temp( 7 downto 0) after k_seq_dly;
						end loop;					
					
						go <= '1' after k_seq_dly;
						auth_data <='1' after k_seq_dly;

						--din_size <="001" after k_seq_dly;				
						din_size <=std_logic_vector(to_unsigned((num_n - cnt_b),5)) after k_seq_dly;				
						last <= '1' after k_seq_dly;
						st <= bubble_p after k_seq_dly;	
					end if;
				end if;
				
				
			when bubble_p =>
				last <= '0' after k_seq_dly;
				if(ready='1') then
					cnt_b :=0;
					-- first line is a comment
					readline(filein,line_in);
					-- second line is the size of P		
					readline(filein,line_in);	
					read(line_in,num_n);
					
					write(fileout,string'("#P"));
					writeline(fileout,line_out);
					
					st <= write_p after k_seq_dly;	
				end if;				
			when write_p =>
				if(dout_valid='1') then
					temp128(127 downto 0) := dout(127 downto 0);
					for i in 0 to to_integer(unsigned(dout_size))-1 loop
						hwrite(line_out,temp128( 127- i*8 downto (128-8)-i*8));
						writeline(fileout,line_out);
					end loop;									
				end if;		
				if(ready='1') then				
					if(cnt_b+16 < num_n) then						
						go <= '1' after k_seq_dly;
						data <='1' after k_seq_dly;
						for i in 0 to 15 loop
							readline(filein,line_in);
							hread(line_in,temp);
							din ( 127- i*8 downto (128-8)-i*8) <= temp( 7 downto 0) after k_seq_dly;
						end loop;
						din_size <="10000" after k_seq_dly;				
						last <= '0' after k_seq_dly;	
						cnt_b := cnt_b +16;						
					else 
						din <= (others =>'0');
						for i in 0 to (num_n-cnt_b-1) loop
							readline(filein,line_in);
							hread(line_in,temp);
							din ( 127- i*8 downto (128-8)-i*8) <= temp( 7 downto 0) after k_seq_dly;
						end loop;										
						go <= '1' after k_seq_dly;
						data <='1' after k_seq_dly;
						--din_size <="001" after k_seq_dly;				
						din_size <=std_logic_vector(to_unsigned((num_n - cnt_b),5)) after k_seq_dly;				
						last <= '1' after k_seq_dly;
						tag <='1' after k_seq_dly;						
						st <= bubble_tag after k_seq_dly;	
					end if;						
				end if;
			when bubble_tag =>
				if(dout_valid='1') then				
					temp128(127 downto 0) := dout(127 downto 0);
					for i in 0 to to_integer(unsigned(dout_size))-1 loop
						hwrite(line_out,temp128( 127- i*8 downto (128-8)-i*8));
						writeline(fileout,line_out);
					end loop;					
				end if;
				last <= '0' after k_seq_dly;
				st <= wait_tag after k_seq_dly;	
			when wait_tag =>
				last <= '0' after k_seq_dly;
				if(ready='1') then
					st <= next_tag after k_seq_dly;

					write(fileout,string'("#T"));
					writeline(fileout,line_out);

					
					--go <= '1' after k_seq_dly;
					--tag_p_one <='1' after k_seq_dly;

					cnt_b :=0;
				end if;			
				if(dout_valid='1' and ready ='0') then				
				-- wrtie to file cipehrtext and not the tag
					temp128(127 downto 0) := dout(127 downto 0);
					for i in 0 to to_integer(unsigned(dout_size))-1 loop
						hwrite(line_out,temp128( 127- i*8 downto (128-8)-i*8));
						writeline(fileout,line_out);
					end loop;					
				end if;
			when next_tag =>

				temp128(127 downto 0) := dout(127 downto 0);
				for i in 0 to 15 loop
					hwrite(line_out,temp128( 127- i*8 downto (128-8)-i*8));
					writeline(fileout,line_out);
				end loop;	

		
				st <= init after k_seq_dly ;
				soft_reset<='1' after k_seq_dly;
				go <='1' after k_seq_dly;
				
			when STOP =>
				
				if(counter_delay="111111") then
					st <= init after k_seq_dly;
				else 
					counter_delay <= counter_delay +1;
				end if;
			when others =>
				null;
				
			end case;

	end if;
end process;


-- clock generation
clkgen : process
	begin
		clk <= '1';
		loop
				wait for 10 ns;
				clk<=not clk;
		end loop;
	end process;

end tb_dec;
