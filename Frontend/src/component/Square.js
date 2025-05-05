import React from 'react';
import './Square.css';

const Square = ({ value, OnSquareClick }) => {
  return (
    <div 
      className="square" 
      onClick={OnSquareClick}
    >
      {value && <span className={`square-value ${value === 'X' ? 'x-mark' : 'o-mark'}`}>{value}</span>}
    </div>
  );
};

export default Square;
