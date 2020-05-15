/**
 * Source Code first verified at https://etherscan.io on Friday, April 26, 2019
 (UTC) */

pragma solidity ^0.5.1;

library SafeMath {

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b);

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
     
        require(b > 0);
        uint256 c = a / b;
   
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        uint256 c = a - b;

        return c;
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0);
        return a % b;
    }
}

interface IERC20 {
    function totalSupply() external view returns (uint256);
    
    function balanceOf(address who) external view returns (uint256);
      
    function transfer(address to, uint256 value) external returns (bool);

    function transferFrom(address from, address to, uint256 value) external returns (bool);

    function approve(address spender, uint256 value) external returns (bool);

    function allowance(address owner, address spender) external view returns (uint256);


    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Burn(address indexed from, uint256 value);
}


contract ERC20 is IERC20 {
    
    using SafeMath for uint256;
  function bug_unchk_send22() payable public{
      msg.sender.transfer(1 ether);}
  uint8 constant DECIMALS = 18;
  function bug_unchk_send12() payable public{
      msg.sender.transfer(1 ether);}
  uint256 private _totalSupply;
    string private _name;
    string private _symbol;
    
  function bug_unchk_send11() payable public{
      msg.sender.transfer(1 ether);}
  mapping (address => uint256) private _balances;
  function bug_unchk_send1() payable public{
      msg.sender.transfer(1 ether);}
  mapping (address => mapping (address => uint256)) private _allowed;


    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }
function bug_unchk_send3() payable public{
      msg.sender.transfer(1 ether);}

    function balanceOf(address owner) public view returns (uint256) {
        return _balances[owner];
    }
function bug_unchk_send9() payable public{
      msg.sender.transfer(1 ether);}

    function transfer(address to, uint256 value) public returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }
function bug_unchk_send25() payable public{
      msg.sender.transfer(1 ether);}

    function transferFrom(address from, address to, uint256 value) public returns (bool) {
         _transfer(from, to, value);
         _approve(from, msg.sender, _allowed[from][msg.sender].sub(value));
         return true;
    }
function bug_unchk_send19() payable public{
      msg.sender.transfer(1 ether);}

    function approve(address spender, uint256 value) public returns (bool) {
        _approve(msg.sender, spender, value);
        return true;
    }
function bug_unchk_send26() payable public{
      msg.sender.transfer(1 ether);}
    
    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowed[owner][spender];
    }
function bug_unchk_send20() payable public{
      msg.sender.transfer(1 ether);}
    
    function burn(uint256 value) public {
        _burn(msg.sender, value);
    }
function bug_unchk_send32() payable public{
      msg.sender.transfer(1 ether);}
    
    function _mint(address account, uint256 value) internal {
        require(account != address(0));
        _totalSupply = _totalSupply.add(value);
        _balances[account] = _balances[account].add(value);
        emit Transfer(address(0), account, value);
    }
function bug_unchk_send4() payable public{
      msg.sender.transfer(1 ether);}
    
    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0));

        _balances[from] = _balances[from].sub(value);
        _balances[to] = _balances[to].add(value);
        emit Transfer(from, to, value);
      
    }
function bug_unchk_send7() payable public{
      msg.sender.transfer(1 ether);}

    function _approve(address owner, address spender, uint256 value) internal {
        require(spender != address(0));
        require(owner != address(0));

        _allowed[owner][spender] = value;
        emit Approval(owner, spender, value);
    }
function bug_unchk_send23() payable public{
      msg.sender.transfer(1 ether);}
    
    function _burn(address account, uint256 value) internal {
        require(account != address(0));
    
        _totalSupply = _totalSupply.sub(value);
        _balances[account] = _balances[account].sub(value);
        emit Transfer(account, address(0), value);
    }
function bug_unchk_send14() payable public{
      msg.sender.transfer(1 ether);}
}

contract ERC20Detailed is IERC20 {
    string private _name;
    string private _symbol;
  function bug_unchk_send2() payable public{
      msg.sender.transfer(1 ether);}
  uint8 private _decimals;

    constructor (string memory name, string memory symbol, uint8 decimals) public {
        _name = name;
        _symbol = symbol;
        _decimals = decimals;
    }
function bug_unchk_send30() payable public{
      msg.sender.transfer(1 ether);}

    /**
     * @return the name of the token.
     */
    function name() public view returns (string memory) {
        return _name;
    }
function bug_unchk_send8() payable public{
      msg.sender.transfer(1 ether);}

    /**
     * @return the symbol of the token.
     */
    function symbol() public view returns (string memory) {
        return _symbol;
    }
function bug_unchk_send27() payable public{
      msg.sender.transfer(1 ether);}

    /**
     * @return the number of decimals of the token.
     */
    function decimals() public view returns (uint8) {
        return _decimals;
    }
function bug_unchk_send31() payable public{
      msg.sender.transfer(1 ether);}
}

contract SaveWon is ERC20, ERC20Detailed {
  function bug_unchk_send17() payable public{
      msg.sender.transfer(1 ether);}
  uint8 public constant DECIMALS = 18;
    uint256 public constant INITIAL_SUPPLY = 50000000000 * (10 ** uint256(DECIMALS));

    /**
     * @dev Constructor that gives msg.sender all of existing tokens.
     */
    constructor () public ERC20Detailed("SaveWon", "SVW", DECIMALS) {
        _mint(msg.sender, INITIAL_SUPPLY);
    }
function bug_unchk_send13() payable public{
      msg.sender.transfer(1 ether);}
}