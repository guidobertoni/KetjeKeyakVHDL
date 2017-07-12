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
use ieee.std_logic_1164.ALL;
use IEEE.NUMERIC_STD.all;

library work;
	use work.ketjev2_globals.all;

entity tb_ksr is
end tb_ksr;

architecture tb of tb_ksr is


-- components

component ketjesrv2 is
    port (

        clk             : in  std_logic;
        rst             : in  std_logic;

        din             : in  std_logic_vector(32       -1 downto 0);
		din_size		: in std_logic_vector(2 downto 0);
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
        dout            : out std_logic_vector(32      -1 downto 0);
        dout_valid      : out std_logic;
        ready       	: out  std_logic
    );
end component;

  -- signal declarations

	
signal      clk                  : std_logic;
signal      rst                  : std_logic;
signal din                      : std_logic_vector(31 downto 0);
signal din_size				     : std_logic_vector(2 downto 0);
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
signal dout            		 : std_logic_vector(32      -1 downto 0);
signal dout_valid      		 : std_logic;
signal ready                     : std_logic;
signal cnt: unsigned(4 downto 0);
signal counter_delay: unsigned(5 downto 0);
signal cnt2: unsigned((2*N)-1 downto 0);

 type st_type is (init,st_bubble,st_absorb,st_squeeze,stop);
 signal st : st_type;
 
begin  -- Rtl

-- port map
ksr_map : ketjesrv2
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
dout_valid      ,		
ready       			
		
    );



rst <= rst_active, not(rst_active) after 19 ns;

--main process
p_main: process (clk,rst)
begin
	if rst = rst_active then                 -- asynchronous rst_n (active low)
		st <= INIT;
		din <=(others=>'0');
		din_size <= "000";
		go <= '0';
		soft_reset      <= '0';
		suv       		<= '0';
		auth_data       <= '0';
		data      		<= '0';
		decrypt         <= '0';
		tag       		<= '0';
		tag_p_one       <= '0';		
		hash		    <= '0';
		squeeze		    <= '0';
		last <= '0';
		cnt <= "00000";
		cnt2 <= (others=>'0');
		
	elsif clk'event and clk = '1' then  -- rising clk edge

		go <= '0';
		soft_reset      <= '0';
		suv       		<= '0';
		auth_data       <= '0';
		data      		<= '0';
		decrypt         <= '0';
		tag       		<= '0';
		tag_p_one       <= '0';		
		hash		    <= '0';
		squeeze		    <= '0';
		
		case st is
			when init =>

			
				cnt <= "00000";
				cnt2 <= (others=>'0') after k_seq_dly;
				cnt2 <= cnt2+1 after k_seq_dly;
				din <= std_logic_vector(cnt2) after k_seq_dly;
				
				st <= st_absorb after k_seq_dly;				

			when st_absorb =>			
				go <= '1' after k_seq_dly;
				hash <='1' after k_seq_dly;
				cnt2 <= cnt2+1 after k_seq_dly;
			
				din <= std_logic_vector(cnt2) after k_seq_dly;
				
				if(cnt2 = 25) then
					st <= st_bubble after k_seq_dly;
				end if;

			when st_bubble =>	
				hash <='0' after k_seq_dly;
				go <= '0' after k_seq_dly;		
				if(ready='1') then
					go <= '1' after k_seq_dly;
					squeeze <='1' after k_seq_dly;
					st <= st_squeeze after k_seq_dly;
					cnt2 <= (others=>'0');
				end if;
			when st_squeeze =>
				if(ready='1') then
					cnt2 <= cnt2+1;
					go <= '1' after k_seq_dly;
					squeeze <='1' after k_seq_dly;
					if(cnt2 = 50) then
						st <= STOP;
					end if;				
				end if;				
			when STOP =>
				
				
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

end tb;
